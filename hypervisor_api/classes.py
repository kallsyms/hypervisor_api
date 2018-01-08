#!/usr/bin/env python3
from typing import Optional

__all__ = [
    "VMTemplate",
    "VM",
    "VMManager",
    "IPResolver",
]


class VMTemplate(object):
    """
    Class which represents a VM template.
    """
    backend_template_id: str
    description: str
    vnc_enabled: bool

    def __init__(self, backend_template_id: str, description: str = "", vnc_enabled: bool = False):
        self.backend_template_id = backend_template_id
        self.description = description
        self.vnc_enabled = vnc_enabled

    def __repr__(self):
        return f"<VMTemplate {self.backend_template_id}>"


class VM(object):
    """
    Class which represents a VM.
    """
    backend_id: str
    template: VMTemplate
    vnc_password: Optional[str]

    def __init__(self, backend_id: str, template: VMTemplate, vnc_password: Optional[str] = None):
        self.backend_id = backend_id
        self.template = template
        self.vnc_password = vnc_password

    def __repr__(self):
        return f"<VM {self.backend_id} from template {self.template.id}>"


class VMManager:
    """
    Basically the interface that all managers have to conform to. Shouldn't
    directly be used.
    """
    def create_template(self, template_id: str):
        """
        Create everything necessary on the backend for a new template.

        Returns nothing.
        """
        raise NotImplementedError()

    def create_vm(self, vm_template: VMTemplate) -> str:
        """
        Create a new VM from the given template.

        Returns the backend VM id as a string
        """
        raise NotImplementedError()

    def start_vm(self, vm: VM):
        """
        Start the given VM.

        Raises an exception if starting failed.
        """
        raise NotImplementedError()

    def stop_vm(self, vm: VM):
        """
        Stop the VM, but don't delete it.

        Raises an exception if stopping failed.
        """
        raise NotImplementedError()

    def reset_vm(self, vm: VM):
        """
        Press the reset button. This is _not_ the same as reimaging it.

        Raises an exception if the reset failed.
        """
        raise NotImplementedError()

    def delete_vm(self, vm: VM):
        """
        Destroy the VM entirely.

        Raises an exception if the VM could not be deleted.
        """
        raise NotImplementedError()

    def reimage_vm(self, vm: VM) -> str:
        """
        Wipe the old disk image and recrete from the template.

        This just stops, deletes, and recreates a new one.
        Subclasses should reimplement to be more efficient.
        """
        template = vm.template

        self.stop_vm(vm)
        self.delete_vm(vm)
        new_vm = self.create_vm(template)

        return new_vm

    def get_status(self, vm: VM) -> str:
        """
        Gets the status of the given VM

        Returns the status as one of the strings 'running', or 'stopped'
        """
        raise NotImplementedError()


class IPResolver(object):
    """
    Base class which various IP resolvers (normally DHCP) should inherit from for hypervisors
    which don't provide VM IP information natively.
    """
    def get_ip(self, mac: str) -> str:
        """
        Gets the IP address the given MAC should have bound to.

        Returns the IP as a string.
        """
        raise NotImplementedError()
