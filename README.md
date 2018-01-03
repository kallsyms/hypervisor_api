# Hypervisor API
The goal of this library is to provide a backend-agnostic API for managing VMs at a high level, so that other Python-based applications (webapp or CLI) can easily interact with whatever hypervisor(s) you have.

As defined in the `VMManager` base class, the API is basically:
* Create a VM
* Create a template from a VM
* Get VM status
* Start, stop, reset VM
* Delete VM
* Reimage VM


# Currently supported hypervisors
* Proxmox


## But _**Cloud**_
I have servers and I want to be able to use them easily.
