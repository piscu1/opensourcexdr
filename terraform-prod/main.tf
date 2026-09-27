variable "wazuh_password" {
  type        = string
  sensitive   = true
  description = "Shared provisioning password for the ansible user across all VMs"
}

resource "proxmox_virtual_environment_vm" "opnsense_gateway" {
  name      = "OPNsense-Gateway"
  node_name = "pve"
  vm_id     = 100

  clone {
    vm_id = 900
    full  = true
  }

  agent {
    enabled = false
  }

  cpu {
    cores = 4
    type  = "host"
  }

  memory {
    dedicated = 6144
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

  disk {
    datastore_id = "local-zfs"
    interface    = "scsi0"
    size         = 20
  }
}

resource "proxmox_virtual_environment_vm" "windows_dc" {
  name      = "Windows-DC-01"
  node_name = "pve"
  vm_id     = 500
  started   = true

  cpu {
    cores = 2
    type  = "host"
  }

  memory {
    dedicated = 4096
  }

  bios          = "seabios"
  boot_order    = ["scsi0", "ide0"]
  scsi_hardware = "virtio-scsi-single"

  operating_system {
    type = "win10"
  }

  network_device {
    bridge  = "vmbr1"
    vlan_id = 20
    model   = "virtio"
  }

  disk {
    datastore_id = "local-zfs"
    interface    = "scsi0"
    size         = 50
    file_format  = "raw"
  }

  cdrom {
    file_id   = "local:iso/windows-server-2016.iso"
    interface = "ide0"
  }

  disk {
    file_id   = "local:iso/virtio-win.iso"
    interface = "ide1"
  }

  vga {
    type = "std"
  }
}

resource "proxmox_virtual_environment_vm" "windows_client" {
  name      = "Windows-Client-01"
  node_name = "pve"
  vm_id     = 600
  started   = true

  cpu {
    cores = 2
    type  = "host"
  }

  memory {
    dedicated = 4096
  }

  bios          = "seabios"
  boot_order    = ["scsi0", "ide0"]
  scsi_hardware = "virtio-scsi-single"

  operating_system {
    type = "win10"
  }

  network_device {
    bridge  = "vmbr1"
    vlan_id = 30
    model   = "virtio"
  }

  disk {
    datastore_id = "local-zfs"
    interface    = "scsi0"
    size         = 50
    file_format  = "raw"
  }

  cdrom {
    file_id   = "local:iso/Windows10.iso"
    interface = "ide0"
  }

  disk {
    file_id   = "local:iso/virtio-win.iso"
    interface = "ide1"
  }

  vga {
    type = "std"
  }
}

resource "proxmox_virtual_environment_file" "wazuh_setup" {
  content_type = "snippets"
  datastore_id = "local"
  node_name    = "pve"

  source_file {
    path = "wazuh-setup.yml"
  }
}

resource "proxmox_virtual_environment_vm" "wazuh_manager" {
  name      = "WazuhSOCManager"
  node_name = "pve"
  vm_id     = 200
  started   = true

  cpu {
    cores = 4
    type  = "host"
  }

  memory {
    dedicated = 10240
  }

  bios          = "seabios"
  boot_order    = ["scsi0"]
  scsi_hardware = "virtio-scsi-single"

  operating_system {
    type = "l26"
  }

  network_device {
    bridge  = "vmbr1"
    vlan_id = 10
    model   = "virtio"
  }

  disk {
    datastore_id = "local-zfs"
    interface    = "scsi0"
    size         = 60
    file_format  = "raw"
    file_id      = "local:iso/noble-server-cloudimg-amd64.img"
  }

  serial_device {
    device = "socket"
  }

  vga {
    type = "serial0"
  }

  initialization {
    datastore_id = "local-zfs"
    interface    = "scsi1"
    type         = "nocloud"

    ip_config {
      ipv4 {
        address = "10.0.10.5/24"
        gateway = "10.0.10.1"
      }
    }

    dns {
      servers = ["10.0.10.1"]
    }

    user_account {
      username = "ansible"
      password = var.wazuh_password
      keys     = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH6YyX6rXv8N8Uf0XN7b9p5T8W5J6mY7R2V3L4K5J6H7"]
    }

    user_data_file_id = proxmox_virtual_environment_file.wazuh_setup.id
  }
}

resource "proxmox_virtual_environment_file" "openvas_setup" {
  content_type = "snippets"
  datastore_id = "local"
  node_name    = "pve"

  source_file {
    path = "openvas-setup.yml"
  }
}

resource "proxmox_virtual_environment_vm" "openvas" {
  name      = "OpenVAS-Scanner"
  node_name = "pve"
  vm_id     = 300
  started   = true

  cpu {
    cores = 4
    type  = "host"
  }

  memory {
    dedicated = 8192
  }

  bios          = "seabios"
  boot_order    = ["scsi0"]
  scsi_hardware = "virtio-scsi-single"

  operating_system {
    type = "l26"
  }

  network_device {
    bridge  = "vmbr1"
    vlan_id = 10
  }

  disk {
    datastore_id = "local-zfs"
    interface    = "scsi0"
    size         = 60
    file_format  = "raw"
    file_id      = "local:iso/noble-server-cloudimg-amd64.img"
  }

  serial_device {}

  vga {
    type = "serial0"
  }

  initialization {
    datastore_id = "local-zfs"
    interface    = "ide2"
    type         = "nocloud"

    ip_config {
      ipv4 {
        address = "10.0.10.6/24"
        gateway = "10.0.10.1"
      }
    }

    dns {
      servers = ["10.0.10.1"]
    }

    user_account {
      username = "ansible"
      password = var.wazuh_password
      keys     = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH6YyX6rXv8N8Uf0XN7b9p5T8W5J6mY7R2V3L4K5J6H7"]
    }

    user_data_file_id = proxmox_virtual_environment_file.openvas_setup.id
  }
}

resource "proxmox_virtual_environment_file" "edge_docker_setup" {
  content_type = "snippets"
  datastore_id = "local"
  node_name    = "pve"

  source_file {
    path = "edge-docker-setup.yml"
  }
}

resource "proxmox_virtual_environment_vm" "edge_docker" {
  name      = "edge-docker"
  node_name = "pve"
  vm_id     = 400
  started   = true

  cpu {
    cores = 2
    type  = "host"
  }

  memory {
    dedicated = 4096
  }

  bios          = "seabios"
  boot_order    = ["scsi0"]
  scsi_hardware = "virtio-scsi-single"

  operating_system {
    type = "l26"
  }

  network_device {
    bridge  = "vmbr1"
    vlan_id = 40
  }

  disk {
    datastore_id = "local-zfs"
    interface    = "scsi0"
    size         = 20
    file_format  = "raw"
    file_id      = "local:iso/noble-server-cloudimg-amd64.img"
  }

  serial_device {}

  vga {
    type = "serial0"
  }

  initialization {
    datastore_id = "local-zfs"
    interface    = "scsi1"
    type         = "nocloud"

    ip_config {
      ipv4 {
        address = "10.0.40.5/24"
        gateway = "10.0.40.1"
      }
    }

    dns {
      servers = ["10.0.40.1"]
    }

    user_account {
      username = "ansible"
      password = var.wazuh_password
      keys     = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH6YyX6rXv8N8Uf0XN7b9p5T8W5J6mY7R2V3L4K5J6H7"]
    }

    user_data_file_id = proxmox_virtual_environment_file.edge_docker_setup.id
  }
}
