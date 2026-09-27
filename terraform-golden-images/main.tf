variable "wazuh_password" {
  type      = string
  sensitive = true
}

resource "proxmox_virtual_environment_vm" "opnsense_golden" {
  name      = "OPNsense-Golden-Template"
  node_name = "pve"
  vm_id     = 900
  started   = false

  agent {
    enabled = false
  }

  cpu {
    cores = 2
    type  = "host"
  }

  memory {
    dedicated = 2048
  }

  network_device {
    bridge = "vmbr0"
    model  = "virtio"
  }

  network_device {
    bridge = "vmbr1"
    model  = "virtio"
    trunks = "10;20;30;40"
  }

  operating_system {
    type = "l26"
  }

  cdrom {
    file_id   = "local:iso/OPNsense-26.1.2-dvd-amd64.iso"
    interface = "ide0"
  }

  disk {
    datastore_id = "local-zfs"
    interface    = "scsi0"
    size         = 20
    file_format  = "raw"
  }
}