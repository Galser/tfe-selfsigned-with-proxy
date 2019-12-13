# EBS volume
resource "aws_ebs_volume" "tfe_disk" {
  availability_zone = var.availabilityZone
  size              = var.size
  tags = {
    collect_tag = var.tag
    name        = var.name
  }
}

# EBS volume attachment
resource "aws_volume_attachment" "tfe_attachment" {
  device_name = var.device_name
  volume_id   = aws_ebs_volume.tfe_disk.id
  instance_id = var.instance_id
}


# Provision EBS volumes
resource "null_resource" "ebs-provision" {
  triggers = {
    esb_volumes_ids = "${aws_ebs_volume.tfe_disk.id}, ${var.instance_id}"
  }

  connection {
    user        = "ubuntu"
    type        = "ssh"
    private_key = file(var.key_path)
    host        = var.instance_ip
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/mount-ebs.sh",
      "/tmp/mount-ebs.sh ${aws_ebs_volume.tfe_disk.id} ${var.device_name} ${var.mount_point}",
    ]
  }

}
