variable "instance_id" {
  description = "Instance ID for attachment"
}

variable "instance_ip" {
  description = "Instance IP to connect and mount disk"
}

variable "device_name" {
  description = "Device name like /dev/xvda or nvme"
}

variable "mount_point" {
  description = "Local mount point. for example /snapshots"
}

variable "tag" {
  description = "Tag for disks"
}

variable "availabilityZone" {
  description = "Availability zone for EBS"
}

variable "size" {
  description = "Size of disk"
}

variable "key_path" {
  description = "Local SSH key path (private part)"
}

variable "name" {
  description = "Name tag"
}
