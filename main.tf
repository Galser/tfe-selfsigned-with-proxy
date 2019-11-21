# Network : AWS VPC
module "vpc_aws" {
  source = "./modules/vpc_aws"

  region           = var.region
  availabilityZone = var.availabilityZone
  tag              = var.vpc_tag
}

# Network : DNS CloudFlare
module "dns_cloudflare" {
  source = "./modules/dns_cloudflare"

  host         = var.site_record
  domain       = var.site_domain
  cname_target = module.lb_aws.fqdn
  record_ip    = module.compute_aws.public_ip
}

# Network : Load-Balancer, Classical ELB, AWS
module "lb_aws" {
  source = "./modules/lb_aws"

  name            = "ag-clb-${var.site_record}"
  security_groups = ["${module.vpc_aws.elb_security_group_id}"]
  subnets         = ["${module.vpc_aws.subnet_id}"]
  instances       = ["${module.compute_aws.instance_id}"] # <-- take from module
}

# SSH Key : 
module "sshkey_aws" {
  source   = "./modules/sshkey_aws"
  name     = var.site_record
  key_path = "~/.ssh/id_rsa.pub"
}

# Instance : AWS EC2
module "compute_aws" {
  source = "./modules/compute_aws"

  name            = "ag-${var.site_record}"
  ami             = var.amis[var.region]
  instance_type   = var.instance_type
  security_groups = ["${module.vpc_aws.security_group_id}"]
  subnet_id       = module.vpc_aws.subnet_id
  key_name        = module.sshkey_aws.key_id
  key_path        = "~/.ssh/id_rsa"
}


# Disk Storage : EBS , DATA
module "disk_aws_data" {
  source = "./modules/disk_aws"

  name             = "ag-${var.site_record}-data"
  size             = 50 # G
  mount_point      = "/tfe-data"
  device_name      = "/dev/sdf"
  availabilityZone = var.availabilityZone
  instance_id      = module.compute_aws.instance_id
  instance_ip      = module.compute_aws.public_ip
  key_path         = "~/.ssh/id_rsa"
  tag              = "ebs-${var.site_record}-data"
}

# Disk Storage : EBS , SNAPSHOTS
module "disk_aws_snapshots" {
  source = "./modules/disk_aws"

  name             = "ag-${var.site_record}-snapshots"
  size             = 100 # G
  mount_point      = "/tfe-snapshots"
  device_name      = "/dev/sdg"
  availabilityZone = var.availabilityZone
  instance_id      = module.compute_aws.instance_id
  instance_ip      = module.compute_aws.public_ip
  key_path         = "~/.ssh/id_rsa"
  tag              = "ebs-${var.site_record}-snapshots"
}


# Certificate : SSL from Let'sEncrypt
module "sslcert_selfsigned" {

  source = "./modules/sslcert_selfsigned/"

  host   = var.site_record
  domain = var.site_domain
  #dns_provider = "cloudflare"  # not required for this cert
  # provider
}

