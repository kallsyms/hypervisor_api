#!/usr/bin/env python3
from requests_toolbelt.sessions import BaseUrlSession
from typing import Tuple, Optional
import logging
import requests
import time

from .classes import VM, VMTemplate, VMManager, IPResolver
from .exceptions import BadAuthException, OverloadException


class ProxmoxManager(VMManager):
    """
    A VM manager to wrap Proxmox's API.
    """
    def __init__(
            self,
            api_url: str,
            username: str,
            password: str,
            shared_disk: str,
            ip_resolver: IPResolver,
            verify_cert: bool = False,
            create_pool: Optional[str] = None):
        """
        Initialize the Proxmox VM Manager given a valid API URI, username, and
        password. Also needed is a ip_resolver implementation for looking up
        the IPs assigned to new VMs based on their MAC.
        """
        self.logger = logging.getLogger(__name__)
        self.api_url = api_url
        self.username = username
        self.password = password
        self.sess = BaseUrlSession(self.api_url + '/api2/json/')
        self.sess.verify = verify_cert
        self.shared_disk = shared_disk
        self.create_pool = create_pool
        self.ip_resolver = ip_resolver
        self._login()

    def _login(self):
        resp = self.sess.post('access/ticket', data={
            'username': self.username,
            'password': self.password,
        }).json()['data']

        if resp:
            requests.utils.add_dict_to_cookiejar(
                self.sess.cookies,
                {
                    'PVEAuthCookie': resp['ticket']
                }
            )
            self.sess.headers.update({
                'CSRFPreventionToken': resp['CSRFPreventionToken']
            })
        else:
            raise BadAuthException("Failed to authenticate to Proxmox")

    def _ensure_login(self):
        if not self.sess.cookies or self.sess.get('version').status_code != 200:
            self._login()

    def _get_vm_by_id(self, vm_id: int) -> VM:
        resources = self.sess.get('cluster/resources?type=vm').json()['data']
        vms = [r for r in resources if r.get('vmid') == vm_id]
        if not vms:
            return None

        vm = vms[0]
        vm.update(self.sess.get('nodes/{}/{}/config'.format(vm['node'], vm['id'])).json()['data'])

        return vm

    def _choose_node(self, vm: VM) -> str:
        """
        Given the number of required cores and mem (in bytes), decide which
        node to place a new VM on based on how utilized each one is.
        We don't care about disk usage because everything is on shared
        storage.
        """
        stats = self.sess.get('cluster/resources?type=node').json()['data']
        candidates = []

        for node in stats:
            if node['maxmem'] - node['mem'] < vm['maxmem']:
                # If the node is completely out of mem, skip
                self.logger.debug("Skipping node %s as it doesn't have enough mem", node['node'])
                continue

            # TODO: Re-add check for host KVM support

            candidates.append({
                'node': node['node'],
                'cpu_pct': node['cpu'] / node['maxcpu'],
                'mem_pct': node['mem'] / node['maxmem'],
            })

        if len(candidates) == 0:
            raise OverloadException("Cluster overloaded! No nodes with enough memory")

        node = min(candidates, key=lambda vm: vm['mem_pct'])['node']
        self.logger.info("Chose '%s' for a new VM with %d cores and %d mem", node, vm['cores'], vm['maxmem'])
        return node

    def _next_id(self) -> int:
        return int(self.sess.get('cluster/nextid').json()['data'])

    def _wait_for_task(self, node: str, task_id: str):
        if task_id is None:
            raise Exception("Trying to wait on None task id")

        self.logger.info("Waiting on task '%s'", task_id)
        while True:
            status = self.sess.get('nodes/{}/tasks/{}/status'.format(node, task_id)).json()
            if 'data' in status and status['data']['status'] != 'running':
                break

            time.sleep(1)

        if status['data']['exitstatus'] != 'OK':
            raise Exception("Bad exit status on task {}".format(task_id))

        self.logger.info("Task '%s' finished", task_id)

    def create_template(self, template_id: str):
        template_id = int(template_id)
        self.logger.info("Creating template from VMID %d", template_id)

        self._ensure_login()
        # Ensure this is a valid template ID
        vm = self._get_vm_by_id(template_id)

        if vm is None:
            raise ValueError("Template ID {} is not a valid VM".format(template_id))

        # Make sure memory is non-ballooning
        if vm.get('balloon', 0) != 0:
            self.logger.info("Setting memory ballooning to false on VMID %d", template_id)
            task_id = self.sess.post(
                'nodes/{}/{}/config'.format(vm['node'], vm['id']),
                data={'balloon': 0}
            ).json()['data']
            self._wait_for_task(vm['node'], task_id)

        if vm.get(vm['bootdisk']).split(':')[0] != self.shared_disk:
            # Full clone to shared storage, then make the clone a template
            new_id = self._next_id()
            self.logger.info("Cloning VMID %d to shared storage (new VMID %d)", template_id, new_id)

            create_params = {
                'newid': new_id,
                'format': 'qcow2',
                'full': 1,
                'name': '{}-template'.format(vm['name']),
                'storage': self.shared_disk,
            }

            if self.create_pool:
                create_params['pool'] = self.create_pool

            task_id = self.sess.post(
                'nodes/{}/{}/clone'.format(vm['node'], vm['id']),
                data=create_params
            ).json()['data']
            self._wait_for_task(vm['node'], task_id)
            vm = self._get_vm_by_id(new_id)

        if not vm['template']:
            self.logger.info("Making VMID %d into a template", vm['vmid'])
            task_id = self.sess.post(
                'nodes/{}/{}/template'.format(vm['node'], vm['id'])
            )

    def create_vm(self, vm_template: VMTemplate) -> str:
        self._ensure_login()
        template_id = int(vm_template.backend_template_id)

        template_vm = self._get_vm_by_id(template_id)

        if not template_vm['template']:
            raise ValueError("Given template VMID {} is not a template".format(vm_template.backend_template_id))

        new_id = self._next_id()
        self.logger.info("Instantiating template VMID %d to new VMID %d", template_id, new_id)

        clone_params = {
            'newid': new_id,
            'name': '{}-{}'.format(template_vm['name'], new_id),
            'target': self._choose_node(template_vm),
        }

        if self.create_pool:
            clone_params['pool'] = self.create_pool

        task_id = self.sess.post(
            'nodes/{}/{}/clone'.format(template_vm['node'], template_vm['id']),
            data=clone_params
        ).json()['data']
        self._wait_for_task(template_vm['node'], task_id)

        self.logger.info("New VM %d created from template %d", new_id, template_id)

        return str(new_id)

    def start_vm(self, vm: VM):
        self._ensure_login()
        vm_id = int(vm.backend_id)
        pm_vm = self._get_vm_by_id(vm_id)

        self.logger.info("Starting VMID %d", vm_id)

        task_id = self.sess.post(
            'nodes/{}/{}/status/start'.format(pm_vm['node'], pm_vm['id']),
        ).json()['data']
        self._wait_for_task(pm_vm['node'], task_id)

        if vm.template.vnc_enabled:
            self.start_vnc(vm)

    def stop_vm(self, vm: VM):
        self._ensure_login()
        vm_id = int(vm.backend_id)
        pm_vm = self._get_vm_by_id(vm_id)

        self.logger.info("Stopping VMID %d", vm_id)

        task_id = self.sess.post(
            'nodes/{}/{}/status/stop'.format(pm_vm['node'], pm_vm['id']),
        ).json()['data']
        self._wait_for_task(pm_vm['node'], task_id)

    def reset_vm(self, vm: VM):
        self._ensure_login()
        vm_id = int(vm.backend_id)
        pm_vm = self._get_vm_by_id(vm_id)

        self.logger.info("Resetting VMID %d", vm_id)

        task_id = self.sess.post(
            'nodes/{}/{}/status/reset'.format(pm_vm['node'], pm_vm['id']),
        ).json()['data']
        self._wait_for_task(pm_vm['node'], task_id)

    def delete_vm(self, vm: VM):
        self._ensure_login()
        vm_id = int(vm.backend_id)
        pm_vm = self._get_vm_by_id(vm_id)

        self.logger.info("Deleting VMID %d", vm_id)

        task_id = self.sess.delete(
            'nodes/{}/{}'.format(pm_vm['node'], pm_vm['id']),
        ).json()['data']
        self._wait_for_task(pm_vm['node'], task_id)

    def get_status(self, vm: VM):
        self._ensure_login()
        vm_id = int(vm.backend_id)
        pm_vm = self._get_vm_by_id(vm_id)

        if pm_vm is None:
            return None

        return self.sess.get(
            'nodes/{}/{}/status/current'.format(pm_vm['node'], pm_vm['id']),
        ).json()['data'].get('status')

    def start_vnc(self, vm: VM, expire_secs: int = 2*24*60*60):
        self._ensure_login()
        vm_id = int(vm.backend_id)
        pm_vm = self._get_vm_by_id(vm_id)

        self.sess.post(
            'nodes/{}/{}/monitor'.format(pm_vm['node'], pm_vm['id']),
            data={'command': 'change vnc 0.0.0.0:{},password'.format(vm_id)}
        )
        self.sess.post(
            'nodes/{}/{}/monitor'.format(pm_vm['node'], pm_vm['id']),
            data={'command': 'set_password vnc {}'.format(vm.vnc_password)}
        )
        self.sess.post(
            'nodes/{}/{}/monitor'.format(pm_vm['node'], pm_vm['id']),
            data={'command': 'expire_password vnc +{}'.format(expire_secs)}
        )

    def get_vnc_ip_port(self, vm: VM) -> Tuple[str, int]:
        if not vm.template.vnc_enabled:
            return None

        if self.get_status(vm) != 'running':
            return None

        self._ensure_login()
        vm_id = int(vm.backend_id)
        pm_vm = self._get_vm_by_id(vm_id)

        node_ifaces = self.sess.get('nodes/{}/network'.format(pm_vm['node'])).json()['data']
        ip = [iface['address'] for iface in node_ifaces if iface.get('gateway')][0]
        return (ip, 5900 + vm_id)

    def stop_vnc(self, vm: VM):
        self._ensure_login()
        vm_id = int(vm.backend_id)
        pm_vm = self._get_vm_by_id(vm_id)

        self.sess.post(
            'nodes/{}/{}/monitor'.format(pm_vm['node'], pm_vm['id']),
            data={'command': 'change vnc 0'.format(vm_id)}
        )

    def get_ip(self, vm: VM) -> str:
        self._ensure_login()
        vm_id = int(vm.backend_id)
        pm_vm = self._get_vm_by_id(vm_id)

        if 'net0' not in pm_vm:
            return None

        nic = pm_vm['net0'].split(',')[0]
        mac = nic.split('=')[1]

        return self.ip_resolver.get_ip(mac)
