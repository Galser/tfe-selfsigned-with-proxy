# Full run-log of infrastructure destruction

```bash

terraform destroy
module.dns_cloudflare.data.cloudflare_zones.site_zone: Refreshing state...
module.sslcert_letsencrypt.tls_private_key.private_key: Refreshing state... [id=0b6d25c53ec6a2aad6450f06a3ddded138830a20]
module.sslcert_letsencrypt.acme_registration.reg: Refreshing state... [id=https://acme-v02.api.letsencrypt.org/acme/acct/73917747]
module.sslcert_letsencrypt.acme_certificate.certificate: Refreshing state... [id=https://acme-v02.api.letsencrypt.org/acme/cert/04e281d734c9b9be62791479525ccaa4d487]
module.sslcert_letsencrypt.local_file.ssl_private_key_file: Refreshing state... [id=86467b2c5c5c12ecceea245c697fccd5283e1b95]
module.sslcert_letsencrypt.local_file.ssl_cert_file: Refreshing state... [id=9e4c9129656ce59a1435ca006492771600706a20]
module.sslcert_letsencrypt.local_file.ssl_cert_bundle_file: Refreshing state... [id=59470e988f986dc44cca527e46bfcbc27886fa5b]
module.disk_aws_data.aws_ebs_volume.tfe_disk: Refreshing state... [id=vol-086a48cbc7817effd]
aws_acm_certificate.cert: Refreshing state... [id=arn:aws:acm:eu-central-1:729476260648:certificate/4e7c7bd8-f899-4a9f-adfb-6ff70373f9a0]
module.vpc_aws.aws_vpc.ag_tfe: Refreshing state... [id=vpc-0658e2c02c852bece]
module.sshkey_aws.aws_key_pair.sshkey: Refreshing state... [id=tfe-ssc-3]
module.vpc_aws.data.aws_availability_zones.available: Refreshing state...
module.disk_aws_snapshots.aws_ebs_volume.tfe_disk: Refreshing state... [id=vol-0d65560ac7c58defa]
module.vpc_aws.aws_subnet.ag_tfe_Subnet: Refreshing state... [id=subnet-0e56119b8e9aa326c]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_proxy: Refreshing state... [id=sg-0f4822f530e55ee5e]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Refreshing state... [id=sg-0d52f7d19a2142b17]
module.vpc_aws.aws_route_table.ag_tfe_route_table: Refreshing state... [id=rtb-082b4fca0dc8f7a1b]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_db: Refreshing state... [id=sg-085b997e0ca644939]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Refreshing state... [id=igw-02120c87126d87618]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_gitlab: Refreshing state... [id=sg-01f756b5aacbfc67f]
module.vpc_aws.aws_subnet.rds[1]: Refreshing state... [id=subnet-0edd3f4dab57314cb]
module.vpc_aws.aws_subnet.rds[0]: Refreshing state... [id=subnet-06d9a0521af755fd9]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group: Refreshing state... [id=sg-0ff516049c67ca3df]
module.vpc_aws.aws_subnet.rds[2]: Refreshing state... [id=subnet-0b0782783ec4134f6]
module.vpc_aws.aws_route.ag_tfe_internet_access: Refreshing state... [id=r-rtb-082b4fca0dc8f7a1b1080289494]
module.vpc_aws.aws_route_table_association.ag_tfe_association: Refreshing state... [id=rtbassoc-00acdb86bf900249f]
module.squidproxy.aws_instance.squidproxy[0]: Refreshing state... [id=i-0f6ea91f90ae6cbed]
module.gitlab.aws_instance.gitlab[0]: Refreshing state... [id=i-00f38f87320c3b296]
module.compute_aws.aws_instance.ptfe: Refreshing state... [id=i-095592eefe25f74bd]
module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment: Refreshing state... [id=vai-4231403432]
module.dns_cloudflare.cloudflare_record.site_gitlab: Refreshing state... [id=44028fbffde71025c7ea889c45776d2f]
module.disk_aws_data.null_resource.ebs-provision: Refreshing state... [id=7061713338411866867]
module.dns_cloudflare.cloudflare_record.site_backend: Refreshing state... [id=06b2bff13955950de32b515dc713f3b6]
module.disk_aws_data.aws_volume_attachment.tfe_attachment: Refreshing state... [id=vai-3891081781]
module.disk_aws_snapshots.null_resource.ebs-provision: Refreshing state... [id=5926664085042487781]
module.lb_aws.aws_elb.ptfe_lb: Refreshing state... [id=ag-clb-ag-clb-tfe-ssc-3]
module.dns_cloudflare.cloudflare_record.site_lb: Refreshing state... [id=bb77ac3ade18af1ab9fd64d2e8c8932d]

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  - destroy

Terraform will perform the following actions:

  # aws_acm_certificate.cert will be destroyed
  - resource "aws_acm_certificate" "cert" {
      - arn                       = "arn:aws:acm:eu-central-1:729476260648:certificate/4e7c7bd8-f899-4a9f-adfb-6ff70373f9a0" -> null
      - certificate_body          = "d4588f3bad45583f24bc803407b4c244653a5ff6" -> null
      - certificate_chain         = "2d65c3ca2cca3a50b6d9d9b4f158e2f8992fa5e9" -> null
      - domain_name               = "tfe-ssc-3.guselietov.com" -> null
      - domain_validation_options = [] -> null
      - id                        = "arn:aws:acm:eu-central-1:729476260648:certificate/4e7c7bd8-f899-4a9f-adfb-6ff70373f9a0" -> null
      - private_key               = (sensitive value)
      - subject_alternative_names = [] -> null
      - tags                      = {} -> null
      - validation_emails         = [] -> null
      - validation_method         = "NONE" -> null

      - options {
          - certificate_transparency_logging_preference = "DISABLED" -> null
        }
    }

  # module.compute_aws.aws_instance.ptfe will be destroyed
  - resource "aws_instance" "ptfe" {
      - ami                          = "ami-08a162fe1419adb2a" -> null
      - arn                          = "arn:aws:ec2:eu-central-1:729476260648:instance/i-095592eefe25f74bd" -> null
      - associate_public_ip_address  = true -> null
      - availability_zone            = "eu-central-1a" -> null
      - cpu_core_count               = 1 -> null
      - cpu_threads_per_core         = 2 -> null
      - disable_api_termination      = false -> null
      - ebs_optimized                = false -> null
      - get_password_data            = false -> null
      - id                           = "i-095592eefe25f74bd" -> null
      - instance_state               = "running" -> null
      - instance_type                = "m5.large" -> null
      - ipv6_address_count           = 0 -> null
      - ipv6_addresses               = [] -> null
      - key_name                     = "tfe-ssc-3" -> null
      - monitoring                   = false -> null
      - primary_network_interface_id = "eni-03ff9c2f005e2a062" -> null
      - private_dns                  = "ip-10-0-1-133.eu-central-1.compute.internal" -> null
      - private_ip                   = "10.0.1.133" -> null
      - public_dns                   = "ec2-3-122-205-219.eu-central-1.compute.amazonaws.com" -> null
      - public_ip                    = "3.122.205.219" -> null
      - security_groups              = [] -> null
      - source_dest_check            = true -> null
      - subnet_id                    = "subnet-0e56119b8e9aa326c" -> null
      - tags                         = {
          - "Name"      = "ag-tfe-ssc-3-andrii"
          - "andriitag" = "true"
        } -> null
      - tenancy                      = "default" -> null
      - volume_tags                  = {
          - "Name"        = "ag-tfe-ssc-3-andrii"
          - "andriitag"   = "true"
          - "collect_tag" = "ebs-tfe-ssc-3-snapshots"
          - "name"        = "ag-tfe-ssc-3-snapshots"
        } -> null
      - vpc_security_group_ids       = [
          - "sg-0ff516049c67ca3df",
        ] -> null

      - ebs_block_device {
          - delete_on_termination = false -> null
          - device_name           = "/dev/sdf" -> null
          - encrypted             = false -> null
          - iops                  = 150 -> null
          - volume_id             = "vol-086a48cbc7817effd" -> null
          - volume_size           = 50 -> null
          - volume_type           = "gp2" -> null
        }
      - ebs_block_device {
          - delete_on_termination = false -> null
          - device_name           = "/dev/sdg" -> null
          - encrypted             = false -> null
          - iops                  = 300 -> null
          - volume_id             = "vol-0d65560ac7c58defa" -> null
          - volume_size           = 100 -> null
          - volume_type           = "gp2" -> null
        }

      - root_block_device {
          - delete_on_termination = true -> null
          - encrypted             = false -> null
          - iops                  = 150 -> null
          - volume_id             = "vol-0c008418e3bce5e74" -> null
          - volume_size           = 50 -> null
          - volume_type           = "gp2" -> null
        }
    }

  # module.disk_aws_data.aws_ebs_volume.tfe_disk will be destroyed
  - resource "aws_ebs_volume" "tfe_disk" {
      - arn               = "arn:aws:ec2:eu-central-1:729476260648:volume/vol-086a48cbc7817effd" -> null
      - availability_zone = "eu-central-1a" -> null
      - encrypted         = false -> null
      - id                = "vol-086a48cbc7817effd" -> null
      - iops              = 150 -> null
      - size              = 50 -> null
      - tags              = {} -> null
      - type              = "gp2" -> null
    }

  # module.disk_aws_data.aws_volume_attachment.tfe_attachment will be destroyed
  - resource "aws_volume_attachment" "tfe_attachment" {
      - device_name = "/dev/sdf" -> null
      - id          = "vai-3891081781" -> null
      - instance_id = "i-095592eefe25f74bd" -> null
      - volume_id   = "vol-086a48cbc7817effd" -> null
    }

  # module.disk_aws_data.null_resource.ebs-provision will be destroyed
  - resource "null_resource" "ebs-provision" {
      - id       = "7061713338411866867" -> null
      - triggers = {
          - "esb_volumes_ids" = "vol-086a48cbc7817effd, i-095592eefe25f74bd"
        } -> null
    }

  # module.disk_aws_snapshots.aws_ebs_volume.tfe_disk will be destroyed
  - resource "aws_ebs_volume" "tfe_disk" {
      - arn               = "arn:aws:ec2:eu-central-1:729476260648:volume/vol-0d65560ac7c58defa" -> null
      - availability_zone = "eu-central-1a" -> null
      - encrypted         = false -> null
      - id                = "vol-0d65560ac7c58defa" -> null
      - iops              = 300 -> null
      - size              = 100 -> null
      - tags              = {
          - "collect_tag" = "ebs-tfe-ssc-3-snapshots"
          - "name"        = "ag-tfe-ssc-3-snapshots"
        } -> null
      - type              = "gp2" -> null
    }

  # module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment will be destroyed
  - resource "aws_volume_attachment" "tfe_attachment" {
      - device_name = "/dev/sdg" -> null
      - id          = "vai-4231403432" -> null
      - instance_id = "i-095592eefe25f74bd" -> null
      - volume_id   = "vol-0d65560ac7c58defa" -> null
    }

  # module.disk_aws_snapshots.null_resource.ebs-provision will be destroyed
  - resource "null_resource" "ebs-provision" {
      - id       = "5926664085042487781" -> null
      - triggers = {
          - "esb_volumes_ids" = "vol-0d65560ac7c58defa, i-095592eefe25f74bd"
        } -> null
    }

  # module.dns_cloudflare.cloudflare_record.site_backend will be destroyed
  - resource "cloudflare_record" "site_backend" {
      - created_on  = "2019-12-16T15:58:03.301296Z" -> null
      - data        = {} -> null
      - hostname    = "tfe-ssc-3_backend.guselietov.com" -> null
      - id          = "06b2bff13955950de32b515dc713f3b6" -> null
      - metadata    = {
          - "auto_added"             = "false"
          - "managed_by_apps"        = "false"
          - "managed_by_argo_tunnel" = "false"
        } -> null
      - modified_on = "2019-12-16T15:58:03.301296Z" -> null
      - name        = "tfe-ssc-3_backend" -> null
      - priority    = 0 -> null
      - proxiable   = true -> null
      - proxied     = false -> null
      - ttl         = 600 -> null
      - type        = "A" -> null
      - value       = "3.122.205.219" -> null
      - zone_id     = "2032750a75777e59b3bf6c73333ee2b0" -> null
    }

  # module.dns_cloudflare.cloudflare_record.site_gitlab will be destroyed
  - resource "cloudflare_record" "site_gitlab" {
      - created_on  = "2019-12-17T17:25:55.353112Z" -> null
      - data        = {} -> null
      - hostname    = "tfe-ssc-3-gitlab.guselietov.com" -> null
      - id          = "44028fbffde71025c7ea889c45776d2f" -> null
      - metadata    = {
          - "auto_added"             = "false"
          - "managed_by_apps"        = "false"
          - "managed_by_argo_tunnel" = "false"
        } -> null
      - modified_on = "2019-12-17T17:25:55.353112Z" -> null
      - name        = "tfe-ssc-3-gitlab" -> null
      - priority    = 0 -> null
      - proxiable   = true -> null
      - proxied     = false -> null
      - ttl         = 600 -> null
      - type        = "A" -> null
      - value       = "35.157.218.64" -> null
      - zone_id     = "2032750a75777e59b3bf6c73333ee2b0" -> null
    }

  # module.dns_cloudflare.cloudflare_record.site_lb will be destroyed
  - resource "cloudflare_record" "site_lb" {
      - created_on  = "2019-12-16T15:59:57.697356Z" -> null
      - data        = {} -> null
      - hostname    = "tfe-ssc-3.guselietov.com" -> null
      - id          = "bb77ac3ade18af1ab9fd64d2e8c8932d" -> null
      - metadata    = {
          - "auto_added"             = "false"
          - "managed_by_apps"        = "false"
          - "managed_by_argo_tunnel" = "false"
        } -> null
      - modified_on = "2019-12-16T15:59:57.697356Z" -> null
      - name        = "tfe-ssc-3" -> null
      - priority    = 0 -> null
      - proxiable   = true -> null
      - proxied     = false -> null
      - ttl         = 600 -> null
      - type        = "CNAME" -> null
      - value       = "ag-clb-ag-clb-tfe-ssc-3-177845966.eu-central-1.elb.amazonaws.com" -> null
      - zone_id     = "2032750a75777e59b3bf6c73333ee2b0" -> null
    }

  # module.gitlab.aws_instance.gitlab[0] will be destroyed
  - resource "aws_instance" "gitlab" {
      - ami                          = "ami-08a162fe1419adb2a" -> null
      - arn                          = "arn:aws:ec2:eu-central-1:729476260648:instance/i-00f38f87320c3b296" -> null
      - associate_public_ip_address  = true -> null
      - availability_zone            = "eu-central-1a" -> null
      - cpu_core_count               = 1 -> null
      - cpu_threads_per_core         = 2 -> null
      - disable_api_termination      = false -> null
      - ebs_optimized                = false -> null
      - get_password_data            = false -> null
      - id                           = "i-00f38f87320c3b296" -> null
      - instance_state               = "running" -> null
      - instance_type                = "m5.large" -> null
      - ipv6_address_count           = 0 -> null
      - ipv6_addresses               = [] -> null
      - key_name                     = "tfe-ssc-3" -> null
      - monitoring                   = false -> null
      - primary_network_interface_id = "eni-091fbba011e9a7afa" -> null
      - private_dns                  = "ip-10-0-1-177.eu-central-1.compute.internal" -> null
      - private_ip                   = "10.0.1.177" -> null
      - public_dns                   = "ec2-35-157-218-64.eu-central-1.compute.amazonaws.com" -> null
      - public_ip                    = "35.157.218.64" -> null
      - security_groups              = [] -> null
      - source_dest_check            = true -> null
      - subnet_id                    = "subnet-0e56119b8e9aa326c" -> null
      - tags                         = {
          - "Name"      = "tfe-ssc-3-gitlab 0 / 1"
          - "andriitag" = "true"
        } -> null
      - tenancy                      = "default" -> null
      - volume_tags                  = {} -> null
      - vpc_security_group_ids       = [
          - "sg-01f756b5aacbfc67f",
        ] -> null

      - root_block_device {
          - delete_on_termination = true -> null
          - encrypted             = false -> null
          - iops                  = 100 -> null
          - volume_id             = "vol-055e4b53dbcc34eca" -> null
          - volume_size           = 8 -> null
          - volume_type           = "gp2" -> null
        }
    }

  # module.lb_aws.aws_elb.ptfe_lb will be destroyed
  - resource "aws_elb" "ptfe_lb" {
      - arn                         = "arn:aws:elasticloadbalancing:eu-central-1:729476260648:loadbalancer/ag-clb-ag-clb-tfe-ssc-3" -> null
      - availability_zones          = [
          - "eu-central-1a",
        ] -> null
      - connection_draining         = true -> null
      - connection_draining_timeout = 400 -> null
      - cross_zone_load_balancing   = true -> null
      - dns_name                    = "ag-clb-ag-clb-tfe-ssc-3-177845966.eu-central-1.elb.amazonaws.com" -> null
      - id                          = "ag-clb-ag-clb-tfe-ssc-3" -> null
      - idle_timeout                = 400 -> null
      - instances                   = [
          - "i-095592eefe25f74bd",
        ] -> null
      - internal                    = false -> null
      - name                        = "ag-clb-ag-clb-tfe-ssc-3" -> null
      - security_groups             = [
          - "sg-0d52f7d19a2142b17",
        ] -> null
      - source_security_group       = "729476260648/ag_ptfe_pm-sg-elb" -> null
      - source_security_group_id    = "sg-0d52f7d19a2142b17" -> null
      - subnets                     = [
          - "subnet-0e56119b8e9aa326c",
        ] -> null
      - tags                        = {
          - "Name"      = "ag-clb-tfe-ssc-3"
          - "andriitag" = "true"
        } -> null
      - zone_id                     = "Z215JYRZR1TBD5" -> null

      - health_check {
          - healthy_threshold   = 3 -> null
          - interval            = 30 -> null
          - target              = "TCP:8800" -> null
          - timeout             = 10 -> null
          - unhealthy_threshold = 10 -> null
        }

      - listener {
          - instance_port      = 443 -> null
          - instance_protocol  = "https" -> null
          - lb_port            = 443 -> null
          - lb_protocol        = "https" -> null
          - ssl_certificate_id = "arn:aws:acm:eu-central-1:729476260648:certificate/4e7c7bd8-f899-4a9f-adfb-6ff70373f9a0" -> null
        }
      - listener {
          - instance_port      = 8800 -> null
          - instance_protocol  = "https" -> null
          - lb_port            = 8800 -> null
          - lb_protocol        = "https" -> null
          - ssl_certificate_id = "arn:aws:acm:eu-central-1:729476260648:certificate/4e7c7bd8-f899-4a9f-adfb-6ff70373f9a0" -> null
        }
    }

  # module.squidproxy.aws_instance.squidproxy[0] will be destroyed
  - resource "aws_instance" "squidproxy" {
      - ami                          = "ami-08a162fe1419adb2a" -> null
      - arn                          = "arn:aws:ec2:eu-central-1:729476260648:instance/i-0f6ea91f90ae6cbed" -> null
      - associate_public_ip_address  = true -> null
      - availability_zone            = "eu-central-1a" -> null
      - cpu_core_count               = 1 -> null
      - cpu_threads_per_core         = 2 -> null
      - disable_api_termination      = false -> null
      - ebs_optimized                = false -> null
      - get_password_data            = false -> null
      - id                           = "i-0f6ea91f90ae6cbed" -> null
      - instance_state               = "running" -> null
      - instance_type                = "m5.large" -> null
      - ipv6_address_count           = 0 -> null
      - ipv6_addresses               = [] -> null
      - key_name                     = "tfe-ssc-3" -> null
      - monitoring                   = false -> null
      - primary_network_interface_id = "eni-0492d328f108de99c" -> null
      - private_dns                  = "ip-10-0-1-66.eu-central-1.compute.internal" -> null
      - private_ip                   = "10.0.1.66" -> null
      - public_dns                   = "ec2-18-194-28-150.eu-central-1.compute.amazonaws.com" -> null
      - public_ip                    = "18.194.28.150" -> null
      - security_groups              = [] -> null
      - source_dest_check            = true -> null
      - subnet_id                    = "subnet-0e56119b8e9aa326c" -> null
      - tags                         = {
          - "Name"      = "tfe-ssc-3-proxy 0 / 1"
          - "andriitag" = "true"
        } -> null
      - tenancy                      = "default" -> null
      - volume_tags                  = {} -> null
      - vpc_security_group_ids       = [
          - "sg-0f4822f530e55ee5e",
        ] -> null

      - root_block_device {
          - delete_on_termination = true -> null
          - encrypted             = false -> null
          - iops                  = 100 -> null
          - volume_id             = "vol-0ad1f0fddaa3fa97d" -> null
          - volume_size           = 8 -> null
          - volume_type           = "gp2" -> null
        }
    }

  # module.sshkey_aws.aws_key_pair.sshkey will be destroyed
  - resource "aws_key_pair" "sshkey" {
      - fingerprint = "01:ca:46:0b:ea:ba:4e:28:0e:c9:b4:9e:2d:f3:29:66" -> null
      - id          = "tfe-ssc-3" -> null
      - key_name    = "tfe-ssc-3" -> null
      - public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC704xhVAxg9Bhq0jIbABWVjKl2DW7apvfFj3UtvActT9a9w1Xt5Fa2jEFuzMXceFtpDjgq5j8E8vsrICu8Wpeqwuo2SR2aAjEjBDfJzOM3kmF9wuWdpacDhVm1luPJiqqM4wLAPufht5vhdlqD8QtW/q84MMHbbkXNjdvgqsIcvDWcCRLQDa1Du3ElF9V+/n182ihIDfQCUtQS0zc9lIcUemZMSLRhxAWA9BZYCu8wnUuLBE/fv8apC0NxOayklSBEj7Pk/HxJnYxTeskqGs5MkzHydObPZSnAtX4Hfe1KlmsAVwt6Sj2bG2AYpt9G0jF7Oq9sYQ6nBTMAxENIsmhB andrii@guselietovs-mbp.home" -> null
    }

  # module.sslcert_letsencrypt.acme_certificate.certificate will be destroyed
  - resource "acme_certificate" "certificate" {
      - account_key_pem    = (sensitive value)
      - certificate_domain = "tfe-ssc-3.guselietov.com" -> null
      - certificate_p12    = (sensitive value)
      - certificate_pem    = <<~EOT
            -----BEGIN CERTIFICATE-----
            MIIFaDCCBFCgAwIBAgISBOKB1zTJub5ieRR5UlzKpNSHMA0GCSqGSIb3DQEBCwUA
            MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
            ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTEyMTYxNDU3MTdaFw0y
            MDAzMTUxNDU3MTdaMCMxITAfBgNVBAMTGHRmZS1zc2MtMy5ndXNlbGlldG92LmNv
            bTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM6N64YvmK4OvydQGxSf
            stH2ZeZDrsRo/OJuuyoatYRmCDyvpTX848u78HpkyZuspm0plA8ThJI3aBIPB1S3
            jIwXZEcZZFNE42QC/GR2dZtY+hQfYhXRzVLU5FQEGCsDWmcabtIbYBMojdvgheTA
            Klf2g0QPavSTvg8nP8oN6oJfX/pPsfNEYbWRE5lZMtkSFKdys1VBdXbPldFhm/AZ
            xlioL5UxYyrF+WsIaZJM1cNS2sdpis4ZlcPiGni1oIcildCc0bdtAkVIGiJAAmjo
            pVb5VMEd0pFRDfUTnfqU5wge+QlpJVjgjNltA4wY2AlBuSHtgkDWs04lK0DlQFV7
            1YsCAwEAAaOCAm0wggJpMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF
            BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUGSfKqOlk26Re
            2W7M6VdrtykfQuQwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYI
            KwYBBQUHAQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0
            c2VuY3J5cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0
            c2VuY3J5cHQub3JnLzAjBgNVHREEHDAaghh0ZmUtc3NjLTMuZ3VzZWxpZXRvdi5j
            b20wTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMBAQEwKDAmBggrBgEF
            BQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggEEBgorBgEEAdZ5AgQC
            BIH1BIHyAPAAdgDwlaRZ8gDRgkAQLS+TiI6tS/4dR+OZ4dA0prCoqo6ycwAAAW8P
            bZTXAAAEAwBHMEUCIHjx4aigslfNgRnDrmO9OKMpnKlFigRTDbTva6HvAulZAiEA
            jsS46eQn0x6cWZxnAMQ8MFyhrihmz4/edWBDZ0jjdsUAdgCyHgXMi6LNiiBOh2b5
            K7mKJSBna9r6cOeySVMt74uQXgAAAW8PbZTJAAAEAwBHMEUCIQDmjP5lLKkPFl/N
            nO35Lh5Cp01eVgQf4s08N1CRLX827QIgMyB7I71EV4eXqFxZVvCRA8Uwgv/Mr4uc
            X4+6x2Dc2MIwDQYJKoZIhvcNAQELBQADggEBAGEH8wwbeuEPdWPIUWENLUZdm4ZZ
            g55Zra2nHlKp7uhZLiY5pI8brt2NdGO1/WNzSGIuzF8ZhnsOYvwZQrDxLK7daqg4
            M9OlzCETB319hTaxp4xHQm1ggu1PBT7T8NpPKeKii2UVNs9MdfWsIv38MqsSv7LY
            RSDKEEgb0aUxAJN4SU7EfIOZ5NS3TepQrEG7JW0ZQMqGiI/7/LC98bVgErQVGgx5
            rud2RwLIDnlOpX4RA6dFfZPVOOfrBN6F5d7OORAIdIxLj2cPPqyljyrTwY1rzX+n
            Int+kx/eSaRqluKvEaj8xXGZYBk+LLR/du4kqJhviu6dtJtf3350u64BTUA=
            -----END CERTIFICATE-----
        EOT -> null
      - certificate_url    = "https://acme-v02.api.letsencrypt.org/acme/cert/04e281d734c9b9be62791479525ccaa4d487" -> null
      - common_name        = "tfe-ssc-3.guselietov.com" -> null
      - id                 = "https://acme-v02.api.letsencrypt.org/acme/cert/04e281d734c9b9be62791479525ccaa4d487" -> null
      - issuer_pem         = <<~EOT
            -----BEGIN CERTIFICATE-----
            MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
            MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
            DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
            SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
            GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
            q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
            SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
            Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
            a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
            /PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
            AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
            CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
            bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
            c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
            VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
            ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
            MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
            Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
            AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
            uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
            wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
            X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
            PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
            KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
            -----END CERTIFICATE-----
        EOT -> null
      - key_type           = "2048" -> null
      - min_days_remaining = 30 -> null
      - must_staple        = false -> null
      - private_key_pem    = (sensitive value)

      - dns_challenge {
          - config   = (sensitive value)
          - provider = "cloudflare" -> null
        }
    }

  # module.sslcert_letsencrypt.acme_registration.reg will be destroyed
  - resource "acme_registration" "reg" {
      - account_key_pem  = (sensitive value)
      - email_address    = "andrii@guselietov.com" -> null
      - id               = "https://acme-v02.api.letsencrypt.org/acme/acct/73917747" -> null
      - registration_url = "https://acme-v02.api.letsencrypt.org/acme/acct/73917747" -> null
    }

  # module.sslcert_letsencrypt.local_file.ssl_cert_bundle_file will be destroyed
  - resource "local_file" "ssl_cert_bundle_file" {
      - directory_permission = "0777" -> null
      - file_permission      = "0777" -> null
      - filename             = "./site_ssl_cert_bundle.pem" -> null
      - id                   = "59470e988f986dc44cca527e46bfcbc27886fa5b" -> null
      - sensitive_content    = (sensitive value)
    }

  # module.sslcert_letsencrypt.local_file.ssl_cert_file will be destroyed
  - resource "local_file" "ssl_cert_file" {
      - directory_permission = "0777" -> null
      - file_permission      = "0777" -> null
      - filename             = "./site_ssl_cert.pem" -> null
      - id                   = "9e4c9129656ce59a1435ca006492771600706a20" -> null
      - sensitive_content    = (sensitive value)
    }

  # module.sslcert_letsencrypt.local_file.ssl_private_key_file will be destroyed
  - resource "local_file" "ssl_private_key_file" {
      - directory_permission = "0777" -> null
      - file_permission      = "0777" -> null
      - filename             = "./site_ssl_private_key.pem" -> null
      - id                   = "86467b2c5c5c12ecceea245c697fccd5283e1b95" -> null
      - sensitive_content    = (sensitive value)
    }

  # module.sslcert_letsencrypt.tls_private_key.private_key will be destroyed
  - resource "tls_private_key" "private_key" {
      - algorithm                  = "RSA" -> null
      - ecdsa_curve                = "P224" -> null
      - id                         = "0b6d25c53ec6a2aad6450f06a3ddded138830a20" -> null
      - private_key_pem            = (sensitive value)
      - public_key_fingerprint_md5 = "3b:bc:19:0b:1e:be:72:cd:df:57:13:fe:96:e4:fe:91" -> null
      - public_key_openssh         = <<~EOT
            ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsKc/8b0d+BVEaKYcIK5XyQa0YbVpqMtyCd5LV0m5iR8q3tY0l+LWAlErz6+azLigVNy/qjofEhO2nHv7pOaz2pWlIo2iveb1BEQX5JVjB+ziqh++TmiXlpEoZb93DDrtuzbUQOcJperumLUu5TfiVulU/I1arocpxs1pvSlX3uzkVl6iFhmJzoQtyxalWLWYQ4eOKTuBIi+Ho4VawETqMd9U5BEMATlHXbSExXkGlDsFsVDKEanEGlex9ZDOpq5q/oUPHeOkPfCTyutwYYzg4R5HsBgLHXD+4rWd6m1YGs8Ds7rcjFXQyyCdgqwDFs6YlCIl468xYV6dz5ZntvPCH
        EOT -> null
      - public_key_pem             = <<~EOT
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCnP/G9HfgVRGimHCCuV
            8kGtGG1aajLcgneS1dJuYkfKt7WNJfi1gJRK8+vmsy4oFTcv6o6HxITtpx7+6Tms
            9qVpSKNor3m9QREF+SVYwfs4qofvk5ol5aRKGW/dww67bs21EDnCaXq7pi1LuU34
            lbpVPyNWq6HKcbNab0pV97s5FZeohYZic6ELcsWpVi1mEOHjik7gSIvh6OFWsBE6
            jHfVOQRDAE5R120hMV5BpQ7BbFQyhGpxBpXsfWQzqauav6FDx3jpD3wk8rrcGGM4
            OEeR7AYCx1w/uK1neptWBrPA7O63IxV0MsgnYKsAxbOmJQiJeOvMWFenc+WZ7bzw
            hwIDAQAB
            -----END PUBLIC KEY-----
        EOT -> null
      - rsa_bits                   = 2048 -> null
    }

  # module.vpc_aws.aws_internet_gateway.ag_tfe_GW will be destroyed
  - resource "aws_internet_gateway" "ag_tfe_GW" {
      - id       = "igw-02120c87126d87618" -> null
      - owner_id = "729476260648" -> null
      - tags     = {
          - "Name" = "ag_ptfe_pm_internet_gateway"
        } -> null
      - vpc_id   = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_route.ag_tfe_internet_access will be destroyed
  - resource "aws_route" "ag_tfe_internet_access" {
      - destination_cidr_block = "0.0.0.0/0" -> null
      - gateway_id             = "igw-02120c87126d87618" -> null
      - id                     = "r-rtb-082b4fca0dc8f7a1b1080289494" -> null
      - origin                 = "CreateRoute" -> null
      - route_table_id         = "rtb-082b4fca0dc8f7a1b" -> null
      - state                  = "active" -> null
    }

  # module.vpc_aws.aws_route_table.ag_tfe_route_table will be destroyed
  - resource "aws_route_table" "ag_tfe_route_table" {
      - id               = "rtb-082b4fca0dc8f7a1b" -> null
      - owner_id         = "729476260648" -> null
      - propagating_vgws = [] -> null
      - route            = [
          - {
              - cidr_block                = "0.0.0.0/0"
              - egress_only_gateway_id    = ""
              - gateway_id                = "igw-02120c87126d87618"
              - instance_id               = ""
              - ipv6_cidr_block           = ""
              - nat_gateway_id            = ""
              - network_interface_id      = ""
              - transit_gateway_id        = ""
              - vpc_peering_connection_id = ""
            },
        ] -> null
      - tags             = {
          - "Name" = "ag_ptfe_pm_route_table"
        } -> null
      - vpc_id           = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_route_table_association.ag_tfe_association will be destroyed
  - resource "aws_route_table_association" "ag_tfe_association" {
      - id             = "rtbassoc-00acdb86bf900249f" -> null
      - route_table_id = "rtb-082b4fca0dc8f7a1b" -> null
      - subnet_id      = "subnet-0e56119b8e9aa326c" -> null
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group will be destroyed
  - resource "aws_security_group" "ag_tfe_Security_Group" {
      - arn                    = "arn:aws:ec2:eu-central-1:729476260648:security-group/sg-0ff516049c67ca3df" -> null
      - description            = "ag_ptfe_pm Security Group" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 1024
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 65535
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 443
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 443
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 80
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 80
            },
        ] -> null
      - id                     = "sg-0ff516049c67ca3df" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 22
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 22
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 443
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 443
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 8800
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 8800
            },
        ] -> null
      - name                   = "ag_ptfe_pm Security Group" -> null
      - owner_id               = "729476260648" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "ag_ptfe_pm_security_group"
        } -> null
      - vpc_id                 = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group_db will be destroyed
  - resource "aws_security_group" "ag_tfe_Security_Group_db" {
      - arn                    = "arn:aws:ec2:eu-central-1:729476260648:security-group/sg-085b997e0ca644939" -> null
      - description            = "ag_ptfe_pm-sg-db" -> null
      - egress                 = [] -> null
      - id                     = "sg-085b997e0ca644939" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 5432
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 5432
            },
        ] -> null
      - name                   = "ag_ptfe_pm-sg-db" -> null
      - owner_id               = "729476260648" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "ag_ptfe_pm_security_group"
        } -> null
      - vpc_id                 = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb will be destroyed
  - resource "aws_security_group" "ag_tfe_Security_Group_elb" {
      - arn                    = "arn:aws:ec2:eu-central-1:729476260648:security-group/sg-0d52f7d19a2142b17" -> null
      - description            = "ag_ptfe_pm ELB Security Group" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - id                     = "sg-0d52f7d19a2142b17" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 443
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 443
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 8800
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 8800
            },
        ] -> null
      - name                   = "ag_ptfe_pm-sg-elb" -> null
      - owner_id               = "729476260648" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {} -> null
      - vpc_id                 = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group_gitlab will be destroyed
  - resource "aws_security_group" "ag_tfe_Security_Group_gitlab" {
      - arn                    = "arn:aws:ec2:eu-central-1:729476260648:security-group/sg-01f756b5aacbfc67f" -> null
      - description            = "ag_ptfe_pm-sg-gitlab" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - id                     = "sg-01f756b5aacbfc67f" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 22
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 22
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 443
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 443
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 80
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 80
            },
        ] -> null
      - name                   = "ag_ptfe_pm-sg-gitlab" -> null
      - owner_id               = "729476260648" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "ag_ptfe_pm_security_group"
        } -> null
      - vpc_id                 = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group_proxy will be destroyed
  - resource "aws_security_group" "ag_tfe_Security_Group_proxy" {
      - arn                    = "arn:aws:ec2:eu-central-1:729476260648:security-group/sg-0f4822f530e55ee5e" -> null
      - description            = "ag_ptfe_pm-sg-proxy" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - id                     = "sg-0f4822f530e55ee5e" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 22
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 22
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 3128
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 3128
            },
        ] -> null
      - name                   = "ag_ptfe_pm-sg-proxy" -> null
      - owner_id               = "729476260648" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "ag_ptfe_pm_security_group"
        } -> null
      - vpc_id                 = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_subnet.ag_tfe_Subnet will be destroyed
  - resource "aws_subnet" "ag_tfe_Subnet" {
      - arn                             = "arn:aws:ec2:eu-central-1:729476260648:subnet/subnet-0e56119b8e9aa326c" -> null
      - assign_ipv6_address_on_creation = false -> null
      - availability_zone               = "eu-central-1a" -> null
      - availability_zone_id            = "euc1-az2" -> null
      - cidr_block                      = "10.0.1.0/24" -> null
      - id                              = "subnet-0e56119b8e9aa326c" -> null
      - map_public_ip_on_launch         = true -> null
      - owner_id                        = "729476260648" -> null
      - tags                            = {
          - "Name" = "ag_ptfe_pm_subnet"
        } -> null
      - vpc_id                          = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_subnet.rds[0] will be destroyed
  - resource "aws_subnet" "rds" {
      - arn                             = "arn:aws:ec2:eu-central-1:729476260648:subnet/subnet-06d9a0521af755fd9" -> null
      - assign_ipv6_address_on_creation = false -> null
      - availability_zone               = "eu-central-1a" -> null
      - availability_zone_id            = "euc1-az2" -> null
      - cidr_block                      = "10.0.3.0/24" -> null
      - id                              = "subnet-06d9a0521af755fd9" -> null
      - map_public_ip_on_launch         = true -> null
      - owner_id                        = "729476260648" -> null
      - tags                            = {} -> null
      - vpc_id                          = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_subnet.rds[1] will be destroyed
  - resource "aws_subnet" "rds" {
      - arn                             = "arn:aws:ec2:eu-central-1:729476260648:subnet/subnet-0edd3f4dab57314cb" -> null
      - assign_ipv6_address_on_creation = false -> null
      - availability_zone               = "eu-central-1b" -> null
      - availability_zone_id            = "euc1-az3" -> null
      - cidr_block                      = "10.0.4.0/24" -> null
      - id                              = "subnet-0edd3f4dab57314cb" -> null
      - map_public_ip_on_launch         = true -> null
      - owner_id                        = "729476260648" -> null
      - tags                            = {} -> null
      - vpc_id                          = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_subnet.rds[2] will be destroyed
  - resource "aws_subnet" "rds" {
      - arn                             = "arn:aws:ec2:eu-central-1:729476260648:subnet/subnet-0b0782783ec4134f6" -> null
      - assign_ipv6_address_on_creation = false -> null
      - availability_zone               = "eu-central-1c" -> null
      - availability_zone_id            = "euc1-az1" -> null
      - cidr_block                      = "10.0.5.0/24" -> null
      - id                              = "subnet-0b0782783ec4134f6" -> null
      - map_public_ip_on_launch         = true -> null
      - owner_id                        = "729476260648" -> null
      - tags                            = {} -> null
      - vpc_id                          = "vpc-0658e2c02c852bece" -> null
    }

  # module.vpc_aws.aws_vpc.ag_tfe will be destroyed
  - resource "aws_vpc" "ag_tfe" {
      - arn                              = "arn:aws:ec2:eu-central-1:729476260648:vpc/vpc-0658e2c02c852bece" -> null
      - assign_generated_ipv6_cidr_block = false -> null
      - cidr_block                       = "10.0.0.0/16" -> null
      - default_network_acl_id           = "acl-0767a5e0134430432" -> null
      - default_route_table_id           = "rtb-0c9702e94a9b901d8" -> null
      - default_security_group_id        = "sg-0898e872f210f0afa" -> null
      - dhcp_options_id                  = "dopt-4f934827" -> null
      - enable_dns_hostnames             = true -> null
      - enable_dns_support               = true -> null
      - id                               = "vpc-0658e2c02c852bece" -> null
      - instance_tenancy                 = "default" -> null
      - main_route_table_id              = "rtb-0c9702e94a9b901d8" -> null
      - owner_id                         = "729476260648" -> null
      - tags                             = {
          - "Name" = "ag_ptfe_pm"
        } -> null
    }

Plan: 0 to add, 0 to change, 35 to destroy.

Do you really want to destroy all resources?
  Terraform will destroy all your managed infrastructure, as shown above.
  There is no undo. Only 'yes' will be accepted to confirm.

  Enter a value: yes


module.sslcert_letsencrypt.local_file.ssl_private_key_file: Destroying... [id=86467b2c5c5c12ecceea245c697fccd5283e1b95]
module.sslcert_letsencrypt.local_file.ssl_cert_bundle_file: Destroying... [id=59470e988f986dc44cca527e46bfcbc27886fa5b]
module.sslcert_letsencrypt.local_file.ssl_cert_file: Destroying... [id=9e4c9129656ce59a1435ca006492771600706a20]
module.dns_cloudflare.cloudflare_record.site_backend: Destroying... [id=06b2bff13955950de32b515dc713f3b6]
module.dns_cloudflare.cloudflare_record.site_gitlab: Destroying... [id=44028fbffde71025c7ea889c45776d2f]
module.dns_cloudflare.cloudflare_record.site_lb: Destroying... [id=bb77ac3ade18af1ab9fd64d2e8c8932d]
module.sslcert_letsencrypt.local_file.ssl_cert_bundle_file: Destruction complete after 0s
module.sslcert_letsencrypt.local_file.ssl_private_key_file: Destruction complete after 0s
module.sslcert_letsencrypt.local_file.ssl_cert_file: Destruction complete after 0s
module.disk_aws_snapshots.null_resource.ebs-provision: Destroying... [id=5926664085042487781]
module.disk_aws_data.null_resource.ebs-provision: Destroying... [id=7061713338411866867]
module.disk_aws_data.null_resource.ebs-provision: Destruction complete after 0s
module.disk_aws_snapshots.null_resource.ebs-provision: Destruction complete after 0s
module.dns_cloudflare.cloudflare_record.site_backend: Destruction complete after 0s
module.dns_cloudflare.cloudflare_record.site_gitlab: Destruction complete after 0s
module.dns_cloudflare.cloudflare_record.site_lb: Destruction complete after 0s
module.vpc_aws.aws_route_table_association.ag_tfe_association: Destroying... [id=rtbassoc-00acdb86bf900249f]
module.disk_aws_data.aws_volume_attachment.tfe_attachment: Destroying... [id=vai-3891081781]
module.vpc_aws.aws_route.ag_tfe_internet_access: Destroying... [id=r-rtb-082b4fca0dc8f7a1b1080289494]
module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment: Destroying... [id=vai-4231403432]
module.vpc_aws.aws_subnet.rds[1]: Destroying... [id=subnet-0edd3f4dab57314cb]
module.vpc_aws.aws_subnet.rds[2]: Destroying... [id=subnet-0b0782783ec4134f6]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_db: Destroying... [id=sg-085b997e0ca644939]
module.vpc_aws.aws_subnet.rds[0]: Destroying... [id=subnet-06d9a0521af755fd9]
module.lb_aws.aws_elb.ptfe_lb: Destroying... [id=ag-clb-ag-clb-tfe-ssc-3]
module.gitlab.aws_instance.gitlab[0]: Destroying... [id=i-00f38f87320c3b296]
module.vpc_aws.aws_route_table_association.ag_tfe_association: Destruction complete after 1s
module.vpc_aws.aws_route.ag_tfe_internet_access: Destruction complete after 1s
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Destroying... [id=igw-02120c87126d87618]
module.squidproxy.aws_instance.squidproxy[0]: Destroying... [id=i-0f6ea91f90ae6cbed]
module.vpc_aws.aws_subnet.rds[0]: Destruction complete after 1s
module.vpc_aws.aws_subnet.rds[2]: Destruction complete after 1s
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_db: Destruction complete after 1s
module.vpc_aws.aws_route_table.ag_tfe_route_table: Destroying... [id=rtb-082b4fca0dc8f7a1b]
module.vpc_aws.aws_subnet.rds[1]: Destruction complete after 1s
module.lb_aws.aws_elb.ptfe_lb: Destruction complete after 1s
aws_acm_certificate.cert: Destroying... [id=arn:aws:acm:eu-central-1:729476260648:certificate/4e7c7bd8-f899-4a9f-adfb-6ff70373f9a0]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Destroying... [id=sg-0d52f7d19a2142b17]
module.vpc_aws.aws_route_table.ag_tfe_route_table: Destruction complete after 0s
aws_acm_certificate.cert: Destruction complete after 2s
module.sslcert_letsencrypt.acme_certificate.certificate: Destroying... [id=https://acme-v02.api.letsencrypt.org/acme/cert/04e281d734c9b9be62791479525ccaa4d487]
module.sslcert_letsencrypt.acme_certificate.certificate: Destruction complete after 1s
module.sslcert_letsencrypt.acme_registration.reg: Destroying... [id=https://acme-v02.api.letsencrypt.org/acme/acct/73917747]
module.sslcert_letsencrypt.acme_registration.reg: Destruction complete after 2s
module.sslcert_letsencrypt.tls_private_key.private_key: Destroying... [id=0b6d25c53ec6a2aad6450f06a3ddded138830a20]
module.sslcert_letsencrypt.tls_private_key.private_key: Destruction complete after 0s
module.disk_aws_data.aws_volume_attachment.tfe_attachment: Still destroying... [id=vai-3891081781, 10s elapsed]
module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment: Still destroying... [id=vai-4231403432, 10s elapsed]
module.gitlab.aws_instance.gitlab[0]: Still destroying... [id=i-00f38f87320c3b296, 10s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 10s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still destroying... [id=i-0f6ea91f90ae6cbed, 10s elapsed]
module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment: Destruction complete after 11s
module.disk_aws_snapshots.aws_ebs_volume.tfe_disk: Destroying... [id=vol-0d65560ac7c58defa]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Still destroying... [id=sg-0d52f7d19a2142b17, 10s elapsed]
module.disk_aws_snapshots.aws_ebs_volume.tfe_disk: Destruction complete after 1s
module.disk_aws_data.aws_volume_attachment.tfe_attachment: Destruction complete after 14s
module.disk_aws_data.aws_ebs_volume.tfe_disk: Destroying... [id=vol-086a48cbc7817effd]
module.compute_aws.aws_instance.ptfe: Destroying... [id=i-095592eefe25f74bd]
module.disk_aws_data.aws_ebs_volume.tfe_disk: Destruction complete after 1s
module.gitlab.aws_instance.gitlab[0]: Still destroying... [id=i-00f38f87320c3b296, 20s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 20s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still destroying... [id=i-0f6ea91f90ae6cbed, 20s elapsed]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Still destroying... [id=sg-0d52f7d19a2142b17, 20s elapsed]
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 10s elapsed]
module.gitlab.aws_instance.gitlab[0]: Still destroying... [id=i-00f38f87320c3b296, 30s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still destroying... [id=i-0f6ea91f90ae6cbed, 30s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 30s elapsed]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Still destroying... [id=sg-0d52f7d19a2142b17, 30s elapsed]
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 20s elapsed]
module.gitlab.aws_instance.gitlab[0]: Still destroying... [id=i-00f38f87320c3b296, 40s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still destroying... [id=i-0f6ea91f90ae6cbed, 40s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 40s elapsed]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Still destroying... [id=sg-0d52f7d19a2142b17, 40s elapsed]
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 30s elapsed]
module.gitlab.aws_instance.gitlab[0]: Still destroying... [id=i-00f38f87320c3b296, 50s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still destroying... [id=i-0f6ea91f90ae6cbed, 50s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 50s elapsed]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Still destroying... [id=sg-0d52f7d19a2142b17, 50s elapsed]
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 40s elapsed]
module.gitlab.aws_instance.gitlab[0]: Still destroying... [id=i-00f38f87320c3b296, 1m0s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 1m0s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still destroying... [id=i-0f6ea91f90ae6cbed, 1m0s elapsed]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Still destroying... [id=sg-0d52f7d19a2142b17, 1m0s elapsed]
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 50s elapsed]
module.gitlab.aws_instance.gitlab[0]: Still destroying... [id=i-00f38f87320c3b296, 1m10s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 1m10s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still destroying... [id=i-0f6ea91f90ae6cbed, 1m10s elapsed]
module.gitlab.aws_instance.gitlab[0]: Destruction complete after 1m11s
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_gitlab: Destroying... [id=sg-01f756b5aacbfc67f]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Still destroying... [id=sg-0d52f7d19a2142b17, 1m10s elapsed]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_gitlab: Destruction complete after 0s
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 1m0s elapsed]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Destruction complete after 1m18s
module.squidproxy.aws_instance.squidproxy[0]: Still destroying... [id=i-0f6ea91f90ae6cbed, 1m20s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 1m20s elapsed]
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 1m10s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still destroying... [id=i-0f6ea91f90ae6cbed, 1m30s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 1m30s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Destruction complete after 1m30s
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_proxy: Destroying... [id=sg-0f4822f530e55ee5e]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_proxy: Destruction complete after 1s
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 1m20s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 1m40s elapsed]
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 1m30s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 1m50s elapsed]
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 1m40s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Still destroying... [id=igw-02120c87126d87618, 2m0s elapsed]
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 1m50s elapsed]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Destruction complete after 2m8s
module.compute_aws.aws_instance.ptfe: Still destroying... [id=i-095592eefe25f74bd, 2m0s elapsed]
module.compute_aws.aws_instance.ptfe: Destruction complete after 2m1s
module.sshkey_aws.aws_key_pair.sshkey: Destroying... [id=tfe-ssc-3]
module.vpc_aws.aws_subnet.ag_tfe_Subnet: Destroying... [id=subnet-0e56119b8e9aa326c]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group: Destroying... [id=sg-0ff516049c67ca3df]
module.sshkey_aws.aws_key_pair.sshkey: Destruction complete after 1s
module.vpc_aws.aws_security_group.ag_tfe_Security_Group: Destruction complete after 1s
module.vpc_aws.aws_subnet.ag_tfe_Subnet: Destruction complete after 1s
module.vpc_aws.aws_vpc.ag_tfe: Destroying... [id=vpc-0658e2c02c852bece]
module.vpc_aws.aws_vpc.ag_tfe: Destruction complete after 0s

Destroy complete! Resources: 35 destroyed.
```