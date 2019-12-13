variable "site_domain" {
  default = "guselietov.com"
}

variable "site_record" {
  default = "tfe-ssc-3"
}

variable "region" {
  default = "eu-central-1"
}

variable "availabilityZone" {
  default = "eu-central-1a"
}

variable "vpc_tag" {
  default = "ag_ptfe_pm"
}

variable "disks_tag" {
  default = "ag_ptfe_pm"
}

variable "amis" {
  type = map
  default = {
    "us-east-2"    = "ami-00f03cfdc90a7a4dd",
    "eu-central-1" = "ami-08a162fe1419adb2a"
  }
}

variable "instance_type" {
  default = "m5.large"
}

variable "db_admin" {
  default = "adimini"
}