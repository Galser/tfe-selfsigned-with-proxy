# Full run log of infra creation (terraform apply)

```bash
terraform apply
module.dns_cloudflare.data.cloudflare_zones.site_zone: Refreshing state...
module.vpc_aws.data.aws_availability_zones.available: Refreshing state...

An execution plan has been generated and is shown below.
Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_acm_certificate.cert will be created
  + resource "aws_acm_certificate" "cert" {
      + arn                       = (known after apply)
      + certificate_body          = (known after apply)
      + certificate_chain         = (known after apply)
      + domain_name               = (known after apply)
      + domain_validation_options = (known after apply)
      + id                        = (known after apply)
      + private_key               = (sensitive value)
      + subject_alternative_names = (known after apply)
      + validation_emails         = (known after apply)
      + validation_method         = (known after apply)
    }

  # module.compute_aws.aws_instance.ptfe will be created
  + resource "aws_instance" "ptfe" {
      + ami                          = "ami-08a162fe1419adb2a"
      + arn                          = (known after apply)
      + associate_public_ip_address  = (known after apply)
      + availability_zone            = (known after apply)
      + cpu_core_count               = (known after apply)
      + cpu_threads_per_core         = (known after apply)
      + get_password_data            = false
      + host_id                      = (known after apply)
      + id                           = (known after apply)
      + instance_state               = (known after apply)
      + instance_type                = "m5.large"
      + ipv6_address_count           = (known after apply)
      + ipv6_addresses               = (known after apply)
      + key_name                     = (known after apply)
      + network_interface_id         = (known after apply)
      + password_data                = (known after apply)
      + placement_group              = (known after apply)
      + primary_network_interface_id = (known after apply)
      + private_dns                  = (known after apply)
      + private_ip                   = (known after apply)
      + public_dns                   = (known after apply)
      + public_ip                    = (known after apply)
      + security_groups              = (known after apply)
      + source_dest_check            = true
      + subnet_id                    = (known after apply)
      + tags                         = {
          + "Name"      = "ag-tfe-ssc-3-andrii"
          + "andriitag" = "true"
        }
      + tenancy                      = (known after apply)
      + volume_tags                  = {
          + "Name"      = "ag-tfe-ssc-3-andrii"
          + "andriitag" = "true"
        }
      + vpc_security_group_ids       = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = true
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = 50
          + volume_type           = (known after apply)
        }
    }

  # module.disk_aws_data.aws_ebs_volume.tfe_disk will be created
  + resource "aws_ebs_volume" "tfe_disk" {
      + arn               = (known after apply)
      + availability_zone = "eu-central-1a"
      + encrypted         = (known after apply)
      + id                = (known after apply)
      + iops              = (known after apply)
      + kms_key_id        = (known after apply)
      + size              = 50
      + snapshot_id       = (known after apply)
      + tags              = {
          + "collect_tag" = "ebs-tfe-ssc-3-data"
          + "name"        = "ag-tfe-ssc-3-data"
        }
      + type              = (known after apply)
    }

  # module.disk_aws_data.aws_volume_attachment.tfe_attachment will be created
  + resource "aws_volume_attachment" "tfe_attachment" {
      + device_name = "/dev/sdf"
      + id          = (known after apply)
      + instance_id = (known after apply)
      + volume_id   = (known after apply)
    }

  # module.disk_aws_data.null_resource.ebs-provision will be created
  + resource "null_resource" "ebs-provision" {
      + id       = (known after apply)
      + triggers = (known after apply)
    }

  # module.disk_aws_snapshots.aws_ebs_volume.tfe_disk will be created
  + resource "aws_ebs_volume" "tfe_disk" {
      + arn               = (known after apply)
      + availability_zone = "eu-central-1a"
      + encrypted         = (known after apply)
      + id                = (known after apply)
      + iops              = (known after apply)
      + kms_key_id        = (known after apply)
      + size              = 100
      + snapshot_id       = (known after apply)
      + tags              = {
          + "collect_tag" = "ebs-tfe-ssc-3-snapshots"
          + "name"        = "ag-tfe-ssc-3-snapshots"
        }
      + type              = (known after apply)
    }

  # module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment will be created
  + resource "aws_volume_attachment" "tfe_attachment" {
      + device_name = "/dev/sdg"
      + id          = (known after apply)
      + instance_id = (known after apply)
      + volume_id   = (known after apply)
    }

  # module.disk_aws_snapshots.null_resource.ebs-provision will be created
  + resource "null_resource" "ebs-provision" {
      + id       = (known after apply)
      + triggers = (known after apply)
    }

  # module.dns_cloudflare.cloudflare_record.site_backend will be created
  + resource "cloudflare_record" "site_backend" {
      + created_on  = (known after apply)
      + hostname    = (known after apply)
      + id          = (known after apply)
      + metadata    = (known after apply)
      + modified_on = (known after apply)
      + name        = "tfe-ssc-3_backend"
      + proxiable   = (known after apply)
      + proxied     = false
      + ttl         = 600
      + type        = "A"
      + value       = (known after apply)
      + zone_id     = "2032750a75777e59b3bf6c73333ee2b0"
    }

  # module.dns_cloudflare.cloudflare_record.site_gitlab will be created
  + resource "cloudflare_record" "site_gitlab" {
      + created_on  = (known after apply)
      + hostname    = (known after apply)
      + id          = (known after apply)
      + metadata    = (known after apply)
      + modified_on = (known after apply)
      + name        = "tfe-ssc-3-gitlab"
      + proxiable   = (known after apply)
      + proxied     = false
      + ttl         = 600
      + type        = "A"
      + value       = (known after apply)
      + zone_id     = "2032750a75777e59b3bf6c73333ee2b0"
    }

  # module.dns_cloudflare.cloudflare_record.site_lb will be created
  + resource "cloudflare_record" "site_lb" {
      + created_on  = (known after apply)
      + hostname    = (known after apply)
      + id          = (known after apply)
      + metadata    = (known after apply)
      + modified_on = (known after apply)
      + name        = "tfe-ssc-3"
      + proxiable   = (known after apply)
      + proxied     = false
      + ttl         = 600
      + type        = "CNAME"
      + value       = (known after apply)
      + zone_id     = "2032750a75777e59b3bf6c73333ee2b0"
    }

  # module.gitlab.aws_instance.gitlab[0] will be created
  + resource "aws_instance" "gitlab" {
      + ami                          = "ami-08a162fe1419adb2a"
      + arn                          = (known after apply)
      + associate_public_ip_address  = (known after apply)
      + availability_zone            = (known after apply)
      + cpu_core_count               = (known after apply)
      + cpu_threads_per_core         = (known after apply)
      + get_password_data            = false
      + host_id                      = (known after apply)
      + id                           = (known after apply)
      + instance_state               = (known after apply)
      + instance_type                = "m5.large"
      + ipv6_address_count           = (known after apply)
      + ipv6_addresses               = (known after apply)
      + key_name                     = (known after apply)
      + network_interface_id         = (known after apply)
      + password_data                = (known after apply)
      + placement_group              = (known after apply)
      + primary_network_interface_id = (known after apply)
      + private_dns                  = (known after apply)
      + private_ip                   = (known after apply)
      + public_dns                   = (known after apply)
      + public_ip                    = (known after apply)
      + security_groups              = (known after apply)
      + source_dest_check            = true
      + subnet_id                    = (known after apply)
      + tags                         = {
          + "Name"      = "tfe-ssc-3-gitlab 0 / 1"
          + "andriitag" = "true"
        }
      + tenancy                      = (known after apply)
      + volume_tags                  = (known after apply)
      + vpc_security_group_ids       = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # module.lb_aws.aws_elb.ptfe_lb will be created
  + resource "aws_elb" "ptfe_lb" {
      + arn                         = (known after apply)
      + availability_zones          = (known after apply)
      + connection_draining         = true
      + connection_draining_timeout = 400
      + cross_zone_load_balancing   = true
      + dns_name                    = (known after apply)
      + id                          = (known after apply)
      + idle_timeout                = 400
      + instances                   = (known after apply)
      + internal                    = (known after apply)
      + name                        = "ag-clb-ag-clb-tfe-ssc-3"
      + security_groups             = (known after apply)
      + source_security_group       = (known after apply)
      + source_security_group_id    = (known after apply)
      + subnets                     = (known after apply)
      + tags                        = {
          + "Name"      = "ag-clb-tfe-ssc-3"
          + "andriitag" = "true"
        }
      + zone_id                     = (known after apply)

      + health_check {
          + healthy_threshold   = 3
          + interval            = 30
          + target              = "TCP:8800"
          + timeout             = 10
          + unhealthy_threshold = 10
        }

      + listener {
          + instance_port      = 443
          + instance_protocol  = "https"
          + lb_port            = 443
          + lb_protocol        = "https"
          + ssl_certificate_id = (known after apply)
        }
      + listener {
          + instance_port      = 8800
          + instance_protocol  = "https"
          + lb_port            = 8800
          + lb_protocol        = "https"
          + ssl_certificate_id = (known after apply)
        }
    }

  # module.squidproxy.aws_instance.squidproxy[0] will be created
  + resource "aws_instance" "squidproxy" {
      + ami                          = "ami-08a162fe1419adb2a"
      + arn                          = (known after apply)
      + associate_public_ip_address  = (known after apply)
      + availability_zone            = (known after apply)
      + cpu_core_count               = (known after apply)
      + cpu_threads_per_core         = (known after apply)
      + get_password_data            = false
      + host_id                      = (known after apply)
      + id                           = (known after apply)
      + instance_state               = (known after apply)
      + instance_type                = "m5.large"
      + ipv6_address_count           = (known after apply)
      + ipv6_addresses               = (known after apply)
      + key_name                     = (known after apply)
      + network_interface_id         = (known after apply)
      + password_data                = (known after apply)
      + placement_group              = (known after apply)
      + primary_network_interface_id = (known after apply)
      + private_dns                  = (known after apply)
      + private_ip                   = (known after apply)
      + public_dns                   = (known after apply)
      + public_ip                    = (known after apply)
      + security_groups              = (known after apply)
      + source_dest_check            = true
      + subnet_id                    = (known after apply)
      + tags                         = {
          + "Name"      = "tfe-ssc-3-proxy 0 / 1"
          + "andriitag" = "true"
        }
      + tenancy                      = (known after apply)
      + volume_tags                  = (known after apply)
      + vpc_security_group_ids       = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # module.sshkey_aws.aws_key_pair.sshkey will be created
  + resource "aws_key_pair" "sshkey" {
      + fingerprint = (known after apply)
      + id          = (known after apply)
      + key_name    = "tfe-ssc-3"
      + public_key  = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC704xhVAxg9Bhq0jIbABWVjKl2DW7apvfFj3UtvActT9a9w1Xt5Fa2jEFuzMXceFtpDjgq5j8E8vsrICu8Wpeqwuo2SR2aAjEjBDfJzOM3kmF9wuWdpacDhVm1luPJiqqM4wLAPufht5vhdlqD8QtW/q84MMHbbkXNjdvgqsIcvDWcCRLQDa1Du3ElF9V+/n182ihIDfQCUtQS0zc9lIcUemZMSLRhxAWA9BZYCu8wnUuLBE/fv8apC0NxOayklSBEj7Pk/HxJnYxTeskqGs5MkzHydObPZSnAtX4Hfe1KlmsAVwt6Sj2bG2AYpt9G0jF7Oq9sYQ6nBTMAxENIsmhB andrii@guselietovs-mbp.home"
    }

  # module.sslcert_letsencrypt.acme_certificate.certificate will be created
  + resource "acme_certificate" "certificate" {
      + account_key_pem    = (sensitive value)
      + certificate_domain = (known after apply)
      + certificate_p12    = (sensitive value)
      + certificate_pem    = (known after apply)
      + certificate_url    = (known after apply)
      + common_name        = "tfe-ssc-3.guselietov.com"
      + id                 = (known after apply)
      + issuer_pem         = (known after apply)
      + key_type           = "2048"
      + min_days_remaining = 30
      + must_staple        = false
      + private_key_pem    = (sensitive value)

      + dns_challenge {
          + provider = "cloudflare"
        }
    }

  # module.sslcert_letsencrypt.acme_registration.reg will be created
  + resource "acme_registration" "reg" {
      + account_key_pem  = (sensitive value)
      + email_address    = "andrii@guselietov.com"
      + id               = (known after apply)
      + registration_url = (known after apply)
    }

  # module.sslcert_letsencrypt.local_file.ssl_cert_bundle_file will be created
  + resource "local_file" "ssl_cert_bundle_file" {
      + directory_permission = "0777"
      + file_permission      = "0777"
      + filename             = "./site_ssl_cert_bundle.pem"
      + id                   = (known after apply)
      + sensitive_content    = (sensitive value)
    }

  # module.sslcert_letsencrypt.local_file.ssl_cert_file will be created
  + resource "local_file" "ssl_cert_file" {
      + directory_permission = "0777"
      + file_permission      = "0777"
      + filename             = "./site_ssl_cert.pem"
      + id                   = (known after apply)
      + sensitive_content    = (sensitive value)
    }

  # module.sslcert_letsencrypt.local_file.ssl_private_key_file will be created
  + resource "local_file" "ssl_private_key_file" {
      + directory_permission = "0777"
      + file_permission      = "0777"
      + filename             = "./site_ssl_private_key.pem"
      + id                   = (known after apply)
      + sensitive_content    = (sensitive value)
    }

  # module.sslcert_letsencrypt.tls_private_key.private_key will be created
  + resource "tls_private_key" "private_key" {
      + algorithm                  = "RSA"
      + ecdsa_curve                = "P224"
      + id                         = (known after apply)
      + private_key_pem            = (sensitive value)
      + public_key_fingerprint_md5 = (known after apply)
      + public_key_openssh         = (known after apply)
      + public_key_pem             = (known after apply)
      + rsa_bits                   = 2048
    }

  # module.vpc_aws.aws_internet_gateway.ag_tfe_GW will be created
  + resource "aws_internet_gateway" "ag_tfe_GW" {
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name" = "ag_ptfe_pm_internet_gateway"
        }
      + vpc_id   = (known after apply)
    }

  # module.vpc_aws.aws_route.ag_tfe_internet_access will be created
  + resource "aws_route" "ag_tfe_internet_access" {
      + destination_cidr_block     = "0.0.0.0/0"
      + destination_prefix_list_id = (known after apply)
      + egress_only_gateway_id     = (known after apply)
      + gateway_id                 = (known after apply)
      + id                         = (known after apply)
      + instance_id                = (known after apply)
      + instance_owner_id          = (known after apply)
      + nat_gateway_id             = (known after apply)
      + network_interface_id       = (known after apply)
      + origin                     = (known after apply)
      + route_table_id             = (known after apply)
      + state                      = (known after apply)
    }

  # module.vpc_aws.aws_route_table.ag_tfe_route_table will be created
  + resource "aws_route_table" "ag_tfe_route_table" {
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name" = "ag_ptfe_pm_route_table"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc_aws.aws_route_table_association.ag_tfe_association will be created
  + resource "aws_route_table_association" "ag_tfe_association" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group will be created
  + resource "aws_security_group" "ag_tfe_Security_Group" {
      + arn                    = (known after apply)
      + description            = "ag_ptfe_pm Security Group"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 1024
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 65535
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 8800
            },
        ]
      + name                   = "ag_ptfe_pm Security Group"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "ag_ptfe_pm_security_group"
        }
      + vpc_id                 = (known after apply)
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group_db will be created
  + resource "aws_security_group" "ag_tfe_Security_Group_db" {
      + arn                    = (known after apply)
      + description            = "ag_ptfe_pm-sg-db"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 5432
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 5432
            },
        ]
      + name                   = "ag_ptfe_pm-sg-db"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "ag_ptfe_pm_security_group"
        }
      + vpc_id                 = (known after apply)
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb will be created
  + resource "aws_security_group" "ag_tfe_Security_Group_elb" {
      + arn                    = (known after apply)
      + description            = "ag_ptfe_pm ELB Security Group"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 8800
            },
        ]
      + name                   = "ag_ptfe_pm-sg-elb"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + vpc_id                 = (known after apply)
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group_gitlab will be created
  + resource "aws_security_group" "ag_tfe_Security_Group_gitlab" {
      + arn                    = (known after apply)
      + description            = "ag_ptfe_pm-sg-gitlab"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
        ]
      + name                   = "ag_ptfe_pm-sg-gitlab"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "ag_ptfe_pm_security_group"
        }
      + vpc_id                 = (known after apply)
    }

  # module.vpc_aws.aws_security_group.ag_tfe_Security_Group_proxy will be created
  + resource "aws_security_group" "ag_tfe_Security_Group_proxy" {
      + arn                    = (known after apply)
      + description            = "ag_ptfe_pm-sg-proxy"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 3128
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 3128
            },
        ]
      + name                   = "ag_ptfe_pm-sg-proxy"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "ag_ptfe_pm_security_group"
        }
      + vpc_id                 = (known after apply)
    }

  # module.vpc_aws.aws_subnet.ag_tfe_Subnet will be created
  + resource "aws_subnet" "ag_tfe_Subnet" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1a"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.0.1.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block                 = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = true
      + owner_id                        = (known after apply)
      + tags                            = {
          + "Name" = "ag_ptfe_pm_subnet"
        }
      + vpc_id                          = (known after apply)
    }

  # module.vpc_aws.aws_subnet.rds[0] will be created
  + resource "aws_subnet" "rds" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1a"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.0.3.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block                 = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = true
      + owner_id                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # module.vpc_aws.aws_subnet.rds[1] will be created
  + resource "aws_subnet" "rds" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1b"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.0.4.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block                 = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = true
      + owner_id                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # module.vpc_aws.aws_subnet.rds[2] will be created
  + resource "aws_subnet" "rds" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1c"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.0.5.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block                 = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = true
      + owner_id                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # module.vpc_aws.aws_vpc.ag_tfe will be created
  + resource "aws_vpc" "ag_tfe" {
      + arn                              = (known after apply)
      + assign_generated_ipv6_cidr_block = false
      + cidr_block                       = "10.0.0.0/16"
      + default_network_acl_id           = (known after apply)
      + default_route_table_id           = (known after apply)
      + default_security_group_id        = (known after apply)
      + dhcp_options_id                  = (known after apply)
      + enable_classiclink               = (known after apply)
      + enable_classiclink_dns_support   = (known after apply)
      + enable_dns_hostnames             = true
      + enable_dns_support               = true
      + id                               = (known after apply)
      + instance_tenancy                 = "default"
      + ipv6_association_id              = (known after apply)
      + ipv6_cidr_block                  = (known after apply)
      + main_route_table_id              = (known after apply)
      + owner_id                         = (known after apply)
      + tags                             = {
          + "Name" = "ag_ptfe_pm"
        }
    }

Plan: 35 to add, 0 to change, 0 to destroy.

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes


module.sslcert_letsencrypt.tls_private_key.private_key: Creating...
module.sslcert_letsencrypt.tls_private_key.private_key: Creation complete after 0s [id=a9e13ceae8491faa73bbcd6d71d1f43934268c09]
module.sslcert_letsencrypt.acme_registration.reg: Creating...
module.sshkey_aws.aws_key_pair.sshkey: Creating...
module.disk_aws_data.aws_ebs_volume.tfe_disk: Creating...
module.disk_aws_snapshots.aws_ebs_volume.tfe_disk: Creating...
module.vpc_aws.aws_vpc.ag_tfe: Creating...
module.sshkey_aws.aws_key_pair.sshkey: Creation complete after 0s [id=tfe-ssc-3]
module.sslcert_letsencrypt.acme_registration.reg: Creation complete after 3s [id=https://acme-v02.api.letsencrypt.org/acme/acct/75068141]
module.sslcert_letsencrypt.acme_certificate.certificate: Creating...
module.vpc_aws.aws_vpc.ag_tfe: Creation complete after 2s [id=vpc-08dc2edd12b7adfb3]
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Creating...
module.vpc_aws.aws_subnet.rds[2]: Creating...
module.vpc_aws.aws_subnet.rds[0]: Creating...
module.vpc_aws.aws_subnet.rds[1]: Creating...
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_db: Creating...
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Creating...
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_gitlab: Creating...
module.vpc_aws.aws_subnet.rds[1]: Creation complete after 1s [id=subnet-0255a0bbb4266d8b8]
module.vpc_aws.aws_subnet.rds[2]: Creation complete after 1s [id=subnet-0a5f7212e9cfe8259]
module.vpc_aws.aws_route_table.ag_tfe_route_table: Creating...
module.vpc_aws.aws_security_group.ag_tfe_Security_Group: Creating...
module.vpc_aws.aws_subnet.rds[0]: Creation complete after 1s [id=subnet-0eefda857a6c86285]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_proxy: Creating...
module.vpc_aws.aws_internet_gateway.ag_tfe_GW: Creation complete after 1s [id=igw-019049e396db9d7a6]
module.vpc_aws.aws_subnet.ag_tfe_Subnet: Creating...
module.vpc_aws.aws_route_table.ag_tfe_route_table: Creation complete after 0s [id=rtb-00f60f37d51e6793a]
module.vpc_aws.aws_route.ag_tfe_internet_access: Creating...
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_elb: Creation complete after 2s [id=sg-0ba8fb0ca18e2cea5]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_db: Creation complete after 2s [id=sg-096e230fc1fad6fdd]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_gitlab: Creation complete after 2s [id=sg-072b53220a129e2c6]
module.vpc_aws.aws_route.ag_tfe_internet_access: Creation complete after 1s [id=r-rtb-00f60f37d51e6793a1080289494]
module.vpc_aws.aws_subnet.ag_tfe_Subnet: Creation complete after 1s [id=subnet-04d7d23c4b3695d22]
module.vpc_aws.aws_route_table_association.ag_tfe_association: Creating...
module.gitlab.aws_instance.gitlab[0]: Creating...
module.vpc_aws.aws_route_table_association.ag_tfe_association: Creation complete after 0s [id=rtbassoc-0d4c1d0cbd802b18d]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group: Creation complete after 2s [id=sg-09a19109bbb2efa43]
module.vpc_aws.aws_security_group.ag_tfe_Security_Group_proxy: Creation complete after 2s [id=sg-031b42fd0df97f848]
module.squidproxy.aws_instance.squidproxy[0]: Creating...
module.compute_aws.aws_instance.ptfe: Creating...
module.sslcert_letsencrypt.acme_certificate.certificate: Creation complete after 8s [id=https://acme-v02.api.letsencrypt.org/acme/cert/03e76a3e31ad47626172296679b7dd90ee41]
module.sslcert_letsencrypt.local_file.ssl_cert_file: Creating...
module.sslcert_letsencrypt.local_file.ssl_cert_bundle_file: Creating...
module.sslcert_letsencrypt.local_file.ssl_private_key_file: Creating...
aws_acm_certificate.cert: Creating...
module.sslcert_letsencrypt.local_file.ssl_cert_file: Creation complete after 0s [id=c495c3e20df1c8c5839a3249d7e734dbf248878a]
module.sslcert_letsencrypt.local_file.ssl_cert_bundle_file: Creation complete after 0s [id=832054e5d47743a981769681627a1abb03529acd]
module.sslcert_letsencrypt.local_file.ssl_private_key_file: Creation complete after 0s [id=6a8973ada973314b7906b01fdde25b2130652caf]
module.disk_aws_snapshots.aws_ebs_volume.tfe_disk: Still creating... [10s elapsed]
module.disk_aws_data.aws_ebs_volume.tfe_disk: Still creating... [10s elapsed]
aws_acm_certificate.cert: Creation complete after 1s [id=arn:aws:acm:eu-central-1:729476260648:certificate/50021f43-33d5-497a-8810-7e733a80a005]
module.disk_aws_data.aws_ebs_volume.tfe_disk: Creation complete after 11s [id=vol-0fae8b37210fe7816]
module.disk_aws_snapshots.aws_ebs_volume.tfe_disk: Creation complete after 11s [id=vol-07aa799a3365631cf]
module.gitlab.aws_instance.gitlab[0]: Still creating... [10s elapsed]
module.compute_aws.aws_instance.ptfe: Still creating... [10s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still creating... [10s elapsed]
module.gitlab.aws_instance.gitlab[0]: Provisioning with 'remote-exec'...
module.gitlab.aws_instance.gitlab[0] (remote-exec): Connecting to remote host via SSH...
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Host: 3.125.34.72
module.gitlab.aws_instance.gitlab[0] (remote-exec):   User: ubuntu
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Password: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Private key: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Certificate: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   SSH Agent: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Checking Host Key: false
module.squidproxy.aws_instance.squidproxy[0]: Provisioning with 'remote-exec'...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Connecting to remote host via SSH...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Host: 18.185.109.208
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   User: ubuntu
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Password: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Private key: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Certificate: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   SSH Agent: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Checking Host Key: false
module.compute_aws.aws_instance.ptfe: Provisioning with 'remote-exec'...
module.compute_aws.aws_instance.ptfe (remote-exec): Connecting to remote host via SSH...
module.compute_aws.aws_instance.ptfe (remote-exec):   Host: 54.93.218.18
module.compute_aws.aws_instance.ptfe (remote-exec):   User: ubuntu
module.compute_aws.aws_instance.ptfe (remote-exec):   Password: false
module.compute_aws.aws_instance.ptfe (remote-exec):   Private key: true
module.compute_aws.aws_instance.ptfe (remote-exec):   Certificate: false
module.compute_aws.aws_instance.ptfe (remote-exec):   SSH Agent: true
module.compute_aws.aws_instance.ptfe (remote-exec):   Checking Host Key: false
module.gitlab.aws_instance.gitlab[0]: Still creating... [20s elapsed]
module.compute_aws.aws_instance.ptfe: Still creating... [20s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still creating... [20s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Connecting to remote host via SSH...
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Host: 3.125.34.72
module.gitlab.aws_instance.gitlab[0] (remote-exec):   User: ubuntu
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Password: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Private key: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Certificate: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   SSH Agent: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Checking Host Key: false
module.gitlab.aws_instance.gitlab[0] (remote-exec): Connecting to remote host via SSH...
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Host: 3.125.34.72
module.gitlab.aws_instance.gitlab[0] (remote-exec):   User: ubuntu
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Password: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Private key: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Certificate: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   SSH Agent: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Checking Host Key: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Connecting to remote host via SSH...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Host: 18.185.109.208
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   User: ubuntu
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Password: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Private key: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Certificate: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   SSH Agent: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Checking Host Key: false
module.compute_aws.aws_instance.ptfe (remote-exec): Connecting to remote host via SSH...
module.compute_aws.aws_instance.ptfe (remote-exec):   Host: 54.93.218.18
module.compute_aws.aws_instance.ptfe (remote-exec):   User: ubuntu
module.compute_aws.aws_instance.ptfe (remote-exec):   Password: false
module.compute_aws.aws_instance.ptfe (remote-exec):   Private key: true
module.compute_aws.aws_instance.ptfe (remote-exec):   Certificate: false
module.compute_aws.aws_instance.ptfe (remote-exec):   SSH Agent: true
module.compute_aws.aws_instance.ptfe (remote-exec):   Checking Host Key: false
module.gitlab.aws_instance.gitlab[0]: Still creating... [30s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Connecting to remote host via SSH...
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Host: 3.125.34.72
module.gitlab.aws_instance.gitlab[0] (remote-exec):   User: ubuntu
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Password: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Private key: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Certificate: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   SSH Agent: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Checking Host Key: false
module.compute_aws.aws_instance.ptfe: Still creating... [30s elapsed]
module.squidproxy.aws_instance.squidproxy[0]: Still creating... [30s elapsed]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Connecting to remote host via SSH...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Host: 18.185.109.208
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   User: ubuntu
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Password: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Private key: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Certificate: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   SSH Agent: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Checking Host Key: false
module.compute_aws.aws_instance.ptfe (remote-exec): Connecting to remote host via SSH...
module.compute_aws.aws_instance.ptfe (remote-exec):   Host: 54.93.218.18
module.compute_aws.aws_instance.ptfe (remote-exec):   User: ubuntu
module.compute_aws.aws_instance.ptfe (remote-exec):   Password: false
module.compute_aws.aws_instance.ptfe (remote-exec):   Private key: true
module.compute_aws.aws_instance.ptfe (remote-exec):   Certificate: false
module.compute_aws.aws_instance.ptfe (remote-exec):   SSH Agent: true
module.compute_aws.aws_instance.ptfe (remote-exec):   Checking Host Key: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Connecting to remote host via SSH...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Host: 18.185.109.208
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   User: ubuntu
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Password: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Private key: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Certificate: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   SSH Agent: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Checking Host Key: false
module.compute_aws.aws_instance.ptfe (remote-exec): Connecting to remote host via SSH...
module.compute_aws.aws_instance.ptfe (remote-exec):   Host: 54.93.218.18
module.compute_aws.aws_instance.ptfe (remote-exec):   User: ubuntu
module.compute_aws.aws_instance.ptfe (remote-exec):   Password: false
module.compute_aws.aws_instance.ptfe (remote-exec):   Private key: true
module.compute_aws.aws_instance.ptfe (remote-exec):   Certificate: false
module.compute_aws.aws_instance.ptfe (remote-exec):   SSH Agent: true
module.compute_aws.aws_instance.ptfe (remote-exec):   Checking Host Key: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Connected!
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Hit:1 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic InRelease
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:2 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates InRelease [88.7 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:3 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports InRelease [74.6 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:4 http://security.ubuntu.com/ubuntu bionic-security InRelease [88.7 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:5 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/universe amd64 Packages [8570 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:6 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/universe Translation-en [4941 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Connected!
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:7 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/multiverse amd64 Packages [151 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:8 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/multiverse Translation-en [108 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:9 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/main amd64 Packages [817 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:10 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/main Translation-en [288 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:11 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/restricted amd64 Packages [24.1 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:12 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/restricted Translation-en [6620 B]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:13 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/universe amd64 Packages [1033 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:14 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/universe Translation-en [319 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:15 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/multiverse amd64 Packages [9284 B]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:16 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/multiverse Translation-en [4508 B]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:17 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports/main amd64 Packages [2512 B]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:18 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports/main Translation-en [1644 B]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:19 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports/universe amd64 Packages [4028 B]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:20 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports/universe Translation-en [1856 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:1 http://security.ubuntu.com/ubuntu bionic-security InRelease [88.7 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:21 http://security.ubuntu.com/ubuntu bionic-security/main amd64 Packages [593 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Hit:2 http://archive.ubuntu.com/ubuntu bionic InRelease
module.compute_aws.aws_instance.ptfe (remote-exec): Get:3 http://archive.ubuntu.com/ubuntu bionic-updates InRelease [88.7 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:22 http://security.ubuntu.com/ubuntu bionic-security/main Translation-en [194 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:23 http://security.ubuntu.com/ubuntu bionic-security/restricted amd64 Packages [15.1 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:24 http://security.ubuntu.com/ubuntu bionic-security/restricted Translation-en [4684 B]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:25 http://security.ubuntu.com/ubuntu bionic-security/universe amd64 Packages [627 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:26 http://security.ubuntu.com/ubuntu bionic-security/universe Translation-en [210 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:4 http://archive.ubuntu.com/ubuntu bionic-backports InRelease [74.6 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:27 http://security.ubuntu.com/ubuntu bionic-security/multiverse amd64 Packages [6120 B]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:28 http://security.ubuntu.com/ubuntu bionic-security/multiverse Translation-en [2600 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:5 http://security.ubuntu.com/ubuntu bionic-security/main amd64 Packages [593 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:6 http://security.ubuntu.com/ubuntu bionic-security/main Translation-en [194 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:7 http://security.ubuntu.com/ubuntu bionic-security/restricted amd64 Packages [15.1 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:8 http://security.ubuntu.com/ubuntu bionic-security/restricted Translation-en [4684 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:9 http://security.ubuntu.com/ubuntu bionic-security/universe amd64 Packages [627 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:10 http://security.ubuntu.com/ubuntu bionic-security/universe Translation-en [210 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:11 http://security.ubuntu.com/ubuntu bionic-security/multiverse amd64 Packages [6120 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:12 http://security.ubuntu.com/ubuntu bionic-security/multiverse Translation-en [2600 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Connecting to remote host via SSH...
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Host: 3.125.34.72
module.gitlab.aws_instance.gitlab[0] (remote-exec):   User: ubuntu
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Password: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Private key: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Certificate: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   SSH Agent: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Checking Host Key: false
module.compute_aws.aws_instance.ptfe (remote-exec): Get:13 http://archive.ubuntu.com/ubuntu bionic/universe amd64 Packages [8570 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:14 http://archive.ubuntu.com/ubuntu bionic/universe Translation-en [4941 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:15 http://archive.ubuntu.com/ubuntu bionic/multiverse amd64 Packages [151 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:16 http://archive.ubuntu.com/ubuntu bionic/multiverse Translation-en [108 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:17 http://archive.ubuntu.com/ubuntu bionic-updates/main amd64 Packages [817 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:18 http://archive.ubuntu.com/ubuntu bionic-updates/main Translation-en [288 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:19 http://archive.ubuntu.com/ubuntu bionic-updates/restricted amd64 Packages [24.1 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:20 http://archive.ubuntu.com/ubuntu bionic-updates/restricted Translation-en [6620 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:21 http://archive.ubuntu.com/ubuntu bionic-updates/universe amd64 Packages [1033 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Connected!
module.compute_aws.aws_instance.ptfe (remote-exec): Get:22 http://archive.ubuntu.com/ubuntu bionic-updates/universe Translation-en [319 kB]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:23 http://archive.ubuntu.com/ubuntu bionic-updates/multiverse amd64 Packages [9284 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:24 http://archive.ubuntu.com/ubuntu bionic-updates/multiverse Translation-en [4508 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:25 http://archive.ubuntu.com/ubuntu bionic-backports/main amd64 Packages [2512 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:26 http://archive.ubuntu.com/ubuntu bionic-backports/main Translation-en [1644 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:27 http://archive.ubuntu.com/ubuntu bionic-backports/universe amd64 Packages [4028 B]
module.compute_aws.aws_instance.ptfe (remote-exec): Get:28 http://archive.ubuntu.com/ubuntu bionic-backports/universe Translation-en [1856 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Hit:1 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic InRelease
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:2 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates InRelease [88.7 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:3 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports InRelease [74.6 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Fetched 18.2 MB in 3s (5657 kB/s)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:4 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/universe amd64 Packages [8570 kB]
module.gitlab.aws_instance.gitlab[0]: Still creating... [40s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:5 http://security.ubuntu.com/ubuntu bionic-security InRelease [88.7 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:6 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/universe Translation-en [4941 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:7 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/multiverse amd64 Packages [151 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:8 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/multiverse Translation-en [108 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:9 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/main amd64 Packages [817 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:10 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/main Translation-en [288 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:11 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/restricted amd64 Packages [24.1 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:12 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/restricted Translation-en [6620 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:13 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/universe amd64 Packages [1033 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:14 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/universe Translation-en [319 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:15 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/multiverse amd64 Packages [9284 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:16 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/multiverse Translation-en [4508 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:17 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports/main amd64 Packages [2512 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:18 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports/main Translation-en [1644 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:19 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports/universe amd64 Packages [4028 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:20 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports/universe Translation-en [1856 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:21 http://security.ubuntu.com/ubuntu bionic-security/main amd64 Packages [593 kB]
module.squidproxy.aws_instance.squidproxy[0]: Still creating... [40s elapsed]
module.compute_aws.aws_instance.ptfe: Still creating... [40s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:22 http://security.ubuntu.com/ubuntu bionic-security/main Translation-en [194 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:23 http://security.ubuntu.com/ubuntu bionic-security/restricted amd64 Packages [15.1 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:24 http://security.ubuntu.com/ubuntu bionic-security/restricted Translation-en [4684 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:25 http://security.ubuntu.com/ubuntu bionic-security/universe amd64 Packages [627 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:26 http://security.ubuntu.com/ubuntu bionic-security/universe Translation-en [210 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:27 http://security.ubuntu.com/ubuntu bionic-security/multiverse amd64 Packages [6120 B]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:28 http://security.ubuntu.com/ubuntu bionic-security/multiverse Translation-en [2600 B]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists...

module.compute_aws.aws_instance.ptfe (remote-exec): Fetched 18.2 MB in 5s (3344 kB/s)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Fetched 18.2 MB in 3s (6016 kB/s)
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree...

module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading state information...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 77 packages can be upgraded. Run 'apt list --upgradable' to see them.
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists...

module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree...

module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading state information...
module.gitlab.aws_instance.gitlab[0] (remote-exec): 77 packages can be upgraded. Run 'apt list --upgradable' to see them.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Hit:1 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic InRelease
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [Connecting to security.ubuntu.com (
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Hit:2 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates InRelease
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Hit:3 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports InRelease
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [Connecting to security.ubuntu.com (
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [1 InRelease gpgv 242 kB] [Connectin
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [Connecting to security.ubuntu.com (
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [2 InRelease gpgv 88.7 kB] [Connecti
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [Waiting for headers]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [3 InRelease gpgv 74.6 kB] [Waiting
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Hit:4 http://security.ubuntu.com/ubuntu bionic-security InRelease
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [3 InRelease gpgv 74.6 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [4 InRelease gpgv 88.7 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 20% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 4%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 4%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 7%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 7%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 7%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 7%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 7%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 7%
module.compute_aws.aws_instance.ptfe (remote-exec): Reading package lists...
module.compute_aws.aws_instance.ptfe (remote-exec): Building dependency tree...
module.compute_aws.aws_instance.ptfe (remote-exec): Reading state information...
module.compute_aws.aws_instance.ptfe (remote-exec): 41 packages can be upgraded. Run 'apt list --upgradable' to see them.
module.compute_aws.aws_instance.ptfe (remote-exec): /usr/bin/curl
module.compute_aws.aws_instance.ptfe: Provisioning with 'file'...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 48%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 48%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 69%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 69%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 70%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 70%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 70%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 70%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 75%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 75%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 78%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 78%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 78%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 78%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 78%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 78%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 85%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 85%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 85%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 87%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 91%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 91%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 93%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 93%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 94%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 94%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 94%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 94%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 97%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 97%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 99%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 99%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 99%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 99%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 99%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 99%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... Done
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree... 50%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree... 50%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading state information... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading state information... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading state information... Done
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 77 packages can be upgraded. Run 'apt list --upgradable' to see them.
module.compute_aws.aws_instance.ptfe: Provisioning with 'file'...
module.compute_aws.aws_instance.ptfe: Creation complete after 47s [id=i-06927b83350bf8836]
module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment: Creating...
module.disk_aws_snapshots.null_resource.ebs-provision: Creating...
module.disk_aws_data.null_resource.ebs-provision: Creating...
module.disk_aws_data.aws_volume_attachment.tfe_attachment: Creating...
module.dns_cloudflare.cloudflare_record.site_backend: Creating...
module.disk_aws_data.null_resource.ebs-provision: Provisioning with 'remote-exec'...
module.disk_aws_snapshots.null_resource.ebs-provision: Provisioning with 'remote-exec'...
module.lb_aws.aws_elb.ptfe_lb: Creating...
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Connecting to remote host via SSH...
module.disk_aws_data.null_resource.ebs-provision (remote-exec):   Host: 54.93.218.18
module.disk_aws_data.null_resource.ebs-provision (remote-exec):   User: ubuntu
module.disk_aws_data.null_resource.ebs-provision (remote-exec):   Password: false
module.disk_aws_data.null_resource.ebs-provision (remote-exec):   Private key: true
module.disk_aws_data.null_resource.ebs-provision (remote-exec):   Certificate: false
module.disk_aws_data.null_resource.ebs-provision (remote-exec):   SSH Agent: true
module.disk_aws_data.null_resource.ebs-provision (remote-exec):   Checking Host Key: false
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Connecting to remote host via SSH...
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec):   Host: 54.93.218.18
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec):   User: ubuntu
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec):   Password: false
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec):   Private key: true
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec):   Certificate: false
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec):   SSH Agent: true
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec):   Checking Host Key: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [Working]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Hit:1 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic InRelease
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [Connecting to security.ubuntu.com (
module.gitlab.aws_instance.gitlab[0] (remote-exec): Hit:2 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates InRelease
module.gitlab.aws_instance.gitlab[0] (remote-exec): Hit:3 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports InRelease
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [Connecting to security.ubuntu.com (
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [1 InRelease gpgv 242 kB] [Connectin
module.gitlab.aws_instance.gitlab[0] (remote-exec): Hit:4 http://security.ubuntu.com/ubuntu bionic-security InRelease
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Connected!
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Connected!
module.dns_cloudflare.cloudflare_record.site_backend: Creation complete after 1s [id=d321a0dd880b6cd161294506e9d8f0e3]
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Looking for attached EBS prod data volume vol-07aa799a3365631cf
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Listing existing Nitro instance volumes (if we have them)
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Looking for attached EBS prod data volume vol-0fae8b37210fe7816
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Listing existing Nitro instance volumes (if we have them)
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): /dev/nvme0    /dev/nvme0n1p1
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): /dev/nvme0n1
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Checkin NVME CLI tools ...
module.disk_aws_data.null_resource.ebs-provision (remote-exec): /dev/nvme0    /dev/nvme0n1p1
module.disk_aws_data.null_resource.ebs-provision (remote-exec): /dev/nvme0n1
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Checkin NVME CLI tools ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [1 InRelease gpgv 242 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [Working]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [2 InRelease gpgv 88.7 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [Working]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [3 InRelease gpgv 74.6 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [Working]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [4 InRelease gpgv 88.7 kB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 20% [Working]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 4%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 4%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 7%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 7%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 7%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 7%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 7%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 7%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Hit:1 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic InRelease
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Hit:2 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates InRelease
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Hit:3 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports InRelease
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Reading package lists...
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Hit:4 http://security.ubuntu.com/ubuntu bionic-security InRelease
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Reading package lists...
module.gitlab.aws_instance.gitlab[0]: Still creating... [50s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 48%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 48%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 69%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 69%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 70%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 70%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 70%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 70%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 75%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 75%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 78%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 78%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 78%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 78%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 78%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 78%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 85%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 85%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 87%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 91%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 91%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 93%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 93%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 94%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 94%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 94%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 94%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 96%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 97%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 97%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 99%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 99%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 99%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 99%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 99%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 99%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... Done
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree... 50%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree... 50%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading state information... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading state information... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading state information... Done
module.gitlab.aws_instance.gitlab[0] (remote-exec): 77 packages can be upgraded. Run 'apt list --upgradable' to see them.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... 100%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading package lists... Done

module.disk_aws_data.null_resource.ebs-provision (remote-exec): E: Could not get lock /var/lib/apt/lists/lock - open (11: Resource temporarily unavailable)
module.disk_aws_data.null_resource.ebs-provision (remote-exec): E: Unable to lock directory /var/lib/apt/lists/
module.disk_aws_data.null_resource.ebs-provision (remote-exec): First APT update failed, retrying.
module.disk_aws_data.null_resource.ebs-provision (remote-exec): .
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree... 50%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree... 50%
module.squidproxy.aws_instance.squidproxy[0]: Still creating... [50s elapsed]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Building dependency tree
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading state information... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading state information... 0%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Reading state information... Done
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): curl is already the newest version (7.58.0-2ubuntu3.8).
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): curl set to manually installed.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): wget is already the newest version (1.19.4-1ubuntu2.2).
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): wget set to manually installed.
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Hit:1 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic InRelease
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Hit:2 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates InRelease
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Hit:3 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-backports InRelease
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): The following additional packages will be installed:
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   libdbi-perl libecap3 libltdl7
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   squid-common squid-langpack ssl-cert
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Suggested packages:
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   libclone-perl libmldbm-perl
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   libnet-daemon-perl
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   libsql-statement-perl squidclient
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   squid-cgi squid-purge resolvconf
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   smbclient winbindd openssl-blacklist
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): The following NEW packages will be installed:
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   libdbi-perl libecap3 libltdl7 squid
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   squid-common squid-langpack ssl-cert
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0 upgraded, 7 newly installed, 0 to remove and 77 not upgraded.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Need to get 3327 kB of archives.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): After this operation, 13.0 MB of additional disk space will be used.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:1 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/main amd64 libecap3 amd64 1.0.1-3.2 [16.6 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 0% [1 libecap3 4096 B/16.6 kB 25%]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 3% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:2 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/main amd64 libltdl7 amd64 2.4.6-2 [38.8 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 3% [2 libltdl7 0 B/38.8 kB 0%]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 7% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:3 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/main amd64 squid-langpack all 20170901-1 [137 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 7% [3 squid-langpack 0 B/137 kB 0%]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 13% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:4 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/main amd64 squid-common all 3.5.27-1ubuntu1.4 [177 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 14% [4 squid-common 16.4 kB/177 kB 9%]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 20% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:5 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/main amd64 libdbi-perl amd64 1.640-1 [724 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 20% [5 libdbi-perl 4096 B/724 kB 1%]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 41% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:6 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/main amd64 ssl-cert all 1.0.39 [17.0 kB]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 41% [6 ssl-cert 17.0 kB/17.0 kB 100%]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 44% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Get:7 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic-updates/main amd64 squid amd64 3.5.27-1ubuntu1.4 [2216 kB]
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Hit:4 http://security.ubuntu.com/ubuntu bionic-security InRelease
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 44% [7 squid 24.2 kB/2216 kB 1%]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): 100% [Working]
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Fetched 3327 kB in 0s (57.4 MB/s)
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Preconfiguring packages ...
                                                            Selecting previously unselected package libecap3:amd64.xy.aws_instance.squidproxy[0] (remote-exec):
module.lb_aws.aws_elb.ptfe_lb: Creation complete after 3s [id=ag-clb-ag-clb-tfe-ssc-3]
module.dns_cloudflare.cloudflare_record.site_lb: Creating...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 5%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 10%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 15%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 20%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 25%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 30%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 35%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 40%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 45%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 50%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 55%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 60%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 65%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 70%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 75%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 80%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 85%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 90%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 95%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 100%
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): (Reading database ... 56534 files and directories currently installed.)
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Preparing to unpack .../0-libecap3_1.0.1-3.2_amd64.deb ...
Progress: [  3%] [..................] oxy[0] (remote-exec): Unpacking libecap3:amd64 (1.0.1-3.2) ...
Progress: [  8%] [#.................] oxy[0] (remote-exec): Selecting previously unselected package libltdl7:amd64.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Preparing to unpack .../1-libltdl7_2.4.6-2_amd64.deb ...
Progress: [ 11%] [#.................] oxy[0] (remote-exec): Unpacking libltdl7:amd64 (2.4.6-2) ...
Progress: [ 17%] [##................] oxy[0] (remote-exec): Selecting previously unselected package squid-langpack.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Preparing to unpack .../2-squid-langpack_20170901-1_all.deb ...
Progress: [ 19%] [###...............] oxy[0] (remote-exec): Unpacking squid-langpack (20170901-1) ...

module.disk_aws_data.null_resource.ebs-provision (remote-exec): Reading package lists...
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Building dependency tree...

module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Reading state information...
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): 77 packages can be upgraded. Run 'apt list --upgradable' to see them.
Progress: [ 25%] [####..............] oxy[0] (remote-exec): Selecting previously unselected package squid-common.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Preparing to unpack .../3-squid-common_3.5.27-1ubuntu1.4_all.deb ...
Progress: [ 28%] [#####.............] oxy[0] (remote-exec): Unpacking squid-common (3.5.27-1ubuntu1.4) ...
Progress: [ 33%] [#####.............] oxy[0] (remote-exec): Selecting previously unselected package libdbi-perl.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Preparing to unpack .../4-libdbi-perl_1.640-1_amd64.deb ...
Progress: [ 36%] [######............] oxy[0] (remote-exec): Unpacking libdbi-perl (1.640-1) ...
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Reading package lists...
Progress: [ 42%] [#######...........] oxy[0] (remote-exec): Selecting previously unselected package ssl-cert.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Preparing to unpack .../5-ssl-cert_1.0.39_all.deb ...
Progress: [ 44%] [#######...........] oxy[0] (remote-exec): Unpacking ssl-cert (1.0.39) ...
Progress: [ 50%] [#########.........] oxy[0] (remote-exec): Selecting previously unselected package squid.
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Preparing to unpack .../6-squid_3.5.27-1ubuntu1.4_amd64.deb ...
Progress: [ 53%] [#########.........] oxy[0] (remote-exec): Unpacking squid (3.5.27-1ubuntu1.4) ...
Progress: [ 58%] [##########........] oxy[0] (remote-exec): Setting up ssl-cert (1.0.39) ...
module.dns_cloudflare.cloudflare_record.site_lb: Creation complete after 1s [id=0e43a1f1754e477645a0ad505c555021]
Progress: [ 61%] [###########.......] oxy[0] (remote-exec):
Progress: [ 64%] [###########.......] oxy[0] (remote-exec): Setting up libecap3:amd64 (1.0.1-3.2) ...
Progress: [ 69%] [############......] oxy[0] (remote-exec): Setting up libltdl7:amd64 (2.4.6-2) ...
Progress: [ 75%] [#############.....] oxy[0] (remote-exec): Setting up squid-langpack (20170901-1) ...
Progress: [ 81%] [##############....] oxy[0] (remote-exec): Setting up squid-common (3.5.27-1ubuntu1.4) ...
Progress: [ 86%] [###############...] oxy[0] (remote-exec): Setting up libdbi-perl (1.640-1) ...
Progress: [ 92%] [################..] oxy[0] (remote-exec): Setting up squid (3.5.27-1ubuntu1.4) ...
Progress: [ 94%] [#################.] oxy[0] (remote-exec): Setcap worked! /usr/lib/squid/pinger is not suid!

module.disk_aws_data.null_resource.ebs-provision (remote-exec): Building dependency tree...

module.disk_aws_data.null_resource.ebs-provision (remote-exec): Reading state information...
module.disk_aws_data.null_resource.ebs-provision (remote-exec): 77 packages can be upgraded. Run 'apt list --upgradable' to see them.
module.disk_aws_data.null_resource.ebs-provision (remote-exec): sudo: nvme: command not found
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Volume with ID : 'vol-0fae8b37210fe7816' not attached yet to the instance, waiting for attachement..

module.disk_aws_data.null_resource.ebs-provision (remote-exec): sudo: nvme: command not found
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Skipping profile in /etc/apparmor.d/disable: usr.sbin.squid
Progress: [ 97%] [#################.] oxy[0] (remote-exec): Processing triggers for systemd (237-3ubuntu10.29) ...
module.disk_aws_data.null_resource.ebs-provision (remote-exec): .
module.gitlab.aws_instance.gitlab[0] (remote-exec): /usr/bin/curl
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Processing triggers for man-db (2.8.3-2ubuntu0.1) ...
module.gitlab.aws_instance.gitlab[0]: Provisioning with 'remote-exec'...
module.gitlab.aws_instance.gitlab[0] (remote-exec): Connecting to remote host via SSH...
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Host: 3.125.34.72
module.gitlab.aws_instance.gitlab[0] (remote-exec):   User: ubuntu
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Password: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Private key: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Certificate: false
module.gitlab.aws_instance.gitlab[0] (remote-exec):   SSH Agent: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):   Checking Host Key: false

module.gitlab.aws_instance.gitlab[0] (remote-exec): Connected!
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Building dependency tree...

module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Reading state information...
module.gitlab.aws_instance.gitlab[0] (remote-exec):   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
module.gitlab.aws_instance.gitlab[0] (remote-exec):                                  Dload  Upload   Total   Spent    Left  Speed
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): The following NEW packages will be installed:
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec):   nvme-cli
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): 0 upgraded, 1 newly installed, 0 to remove and 77 not upgraded.
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Need to get 182 kB of archives.
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): After this operation, 390 kB of additional disk space will be used.
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Get:1 http://eu-central-1.ec2.archive.ubuntu.com/ubuntu bionic/universe amd64 nvme-cli amd64 1.5-1 [182 kB]
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Fetched 182 kB in 0s (0 B/s)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
module.gitlab.aws_instance.gitlab[0] (remote-exec):   0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Processing triggers for ufw (0.36-0ubuntu0.18.04.1) ...
                                                                     Selecting previously unselected package nvme-cli.apshots.null_resource.ebs-provision (remote-exec):
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Processing triggers for ureadahead (0.100.0-21) ...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Processing triggers for libc-bin (2.27-3ubuntu1) ...

module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ...
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 5%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 10%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 15%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 20%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 25%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 30%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 35%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 40%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 45%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 50%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 55%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 60%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 65%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 70%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 75%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 80%
module.gitlab.aws_instance.gitlab[0] (remote-exec): 100  5933    0  5933    0     0   8017      0 --:--:-- --:--:-- --:--:--  8006
module.gitlab.aws_instance.gitlab[0] (remote-exec): Detected operating system as Ubuntu/bionic.
module.gitlab.aws_instance.gitlab[0] (remote-exec): Checking for curl...
module.gitlab.aws_instance.gitlab[0] (remote-exec): Detected curl...
module.gitlab.aws_instance.gitlab[0] (remote-exec): Checking for gpg...
module.gitlab.aws_instance.gitlab[0] (remote-exec): Detected
module.gitlab.aws_instance.gitlab[0] (remote-exec): Running apt-get update...
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 85%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 90%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 95%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 100%
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): (Reading database ... 56534 files and directories currently installed.)
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Preparing to unpack .../nvme-cli_1.5-1_amd64.deb ...
Progress: [ 17%] [##................] e.ebs-provision (remote-exec): Unpacking nvme-cli (1.5-1) ...
Progress: [ 50%] [#########.........] e.ebs-provision (remote-exec): Setting up nvme-cli (1.5-1) ...
Progress: [ 83%] [###############...] e.ebs-provision (remote-exec): Processing triggers for man-db (2.8.3-2ubuntu0.1) ...
module.squidproxy.aws_instance.squidproxy[0]: Provisioning with 'remote-exec'...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Connecting to remote host via SSH...
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Host: 18.185.109.208
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   User: ubuntu
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Password: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Private key: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Certificate: false
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   SSH Agent: true
module.squidproxy.aws_instance.squidproxy[0] (remote-exec):   Checking Host Key: false
module.gitlab.aws_instance.gitlab[0] (remote-exec): done.
module.gitlab.aws_instance.gitlab[0] (remote-exec): Installing apt-transport-https...
module.disk_aws_data.null_resource.ebs-provision (remote-exec): .
module.squidproxy.aws_instance.squidproxy[0] (remote-exec): Connected!

module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Volume with ID : 'vol-07aa799a3365631cf' not attached yet to the instance, waiting for attachement..

module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): .
module.gitlab.aws_instance.gitlab[0] (remote-exec): done.
module.gitlab.aws_instance.gitlab[0] (remote-exec): Installing /etc/apt/sources.list.d/gitlab_gitlab-ee.list...
module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment: Still creating... [10s elapsed]
module.disk_aws_data.null_resource.ebs-provision: Still creating... [10s elapsed]
module.disk_aws_snapshots.null_resource.ebs-provision: Still creating... [10s elapsed]
module.disk_aws_data.aws_volume_attachment.tfe_attachment: Still creating... [10s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): done.
module.gitlab.aws_instance.gitlab[0] (remote-exec): Importing packagecloud gpg key...
module.disk_aws_data.null_resource.ebs-provision (remote-exec): .
module.gitlab.aws_instance.gitlab[0] (remote-exec): done.
module.gitlab.aws_instance.gitlab[0] (remote-exec): Running apt-get update...
module.gitlab.aws_instance.gitlab[0]: Still creating... [1m0s elapsed]
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): .
module.squidproxy.aws_instance.squidproxy[0]: Still creating... [1m0s elapsed]
module.disk_aws_data.null_resource.ebs-provision (remote-exec): .
module.gitlab.aws_instance.gitlab[0] (remote-exec): done.

module.gitlab.aws_instance.gitlab[0] (remote-exec): The repository is setup! You can now install packages.
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... 100%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading package lists... Done
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Checking for late mount
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): /dev/nvme1n1
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Creating file system...
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree... 50%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree... 50%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Building dependency tree
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading state information... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading state information... 0%
module.gitlab.aws_instance.gitlab[0] (remote-exec): Reading state information... Done
module.gitlab.aws_instance.gitlab[0] (remote-exec): The following NEW packages will be installed:
module.gitlab.aws_instance.gitlab[0] (remote-exec):   gitlab-ee
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0 upgraded, 1 newly installed, 0 to remove and 77 not upgraded.
module.gitlab.aws_instance.gitlab[0] (remote-exec): Need to get 811 MB of archives.
module.gitlab.aws_instance.gitlab[0] (remote-exec): After this operation, 2110 MB of additional disk space will be used.
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [Working]
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): . done
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Creating mountpoint... done
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): Mounting volume..
module.disk_aws_snapshots.null_resource.ebs-provision (remote-exec): .done
module.disk_aws_snapshots.null_resource.ebs-provision: Creation complete after 16s [id=7936702660650967059]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [Connected to packages.gitlab.com (5
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [Working]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Get:1 https://packages.gitlab.com/gitlab/gitlab-ee/ubuntu bionic/main amd64 gitlab-ee amd64 12.6.2-ee.0 [811 MB]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 0% [1 gitlab-ee 16.4 kB/811 MB 0%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 3% [1 gitlab-ee 34.5 MB/811 MB 4%]
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Checking for late mount
module.disk_aws_data.null_resource.ebs-provision (remote-exec): /dev/nvme2n1
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Creating file system...
module.disk_aws_data.null_resource.ebs-provision (remote-exec): . done
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Creating mountpoint... done
module.disk_aws_data.null_resource.ebs-provision (remote-exec): Mounting volume...done
module.gitlab.aws_instance.gitlab[0] (remote-exec): 7% [1 gitlab-ee 69.1 MB/811 MB 9%]
module.disk_aws_data.null_resource.ebs-provision: Creation complete after 17s [id=3363225729097939729]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 10% [1 gitlab-ee 103 MB/811 MB 13%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 14% [1 gitlab-ee 138 MB/811 MB 17%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 17% [1 gitlab-ee 172 MB/811 MB 21%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 20% [1 gitlab-ee 207 MB/811 MB 26%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 24% [1 gitlab-ee 242 MB/811 MB 30%]
module.disk_aws_data.aws_volume_attachment.tfe_attachment: Still creating... [20s elapsed]
module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment: Still creating... [20s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 27% [1 gitlab-ee 276 MB/811 MB 34%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 31% [1 gitlab-ee 311 MB/811 MB 38%]
module.disk_aws_snapshots.aws_volume_attachment.tfe_attachment: Creation complete after 21s [id=vai-3035655657]
module.disk_aws_data.aws_volume_attachment.tfe_attachment: Creation complete after 21s [id=vai-3649653132]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 34% [1 gitlab-ee 345 MB/811 MB 43%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 37% [1 gitlab-ee 380 MB/811 MB 47%]
module.gitlab.aws_instance.gitlab[0]: Still creating... [1m10s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 41% [1 gitlab-ee 414 MB/811 MB 51%]
module.squidproxy.aws_instance.squidproxy[0]: Still creating... [1m10s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 44% [1 gitlab-ee 449 MB/811 MB 55%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 48% [1 gitlab-ee 483 MB/811 MB 60%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 51% [1 gitlab-ee 518 MB/811 MB 64%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 54% [1 gitlab-ee 552 MB/811 MB 68%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 58% [1 gitlab-ee 587 MB/811 MB 72%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 61% [1 gitlab-ee 622 MB/811 MB 77%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 65% [1 gitlab-ee 656 MB/811 MB 81%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 68% [1 gitlab-ee 690 MB/811 MB 85%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 71% [1 gitlab-ee 724 MB/811 MB 89%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 75% [1 gitlab-ee 759 MB/811 MB 94%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 78% [1 gitlab-ee 792 MB/811 MB 98%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 80% [1 gitlab-ee 811 MB/811 MB 100%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 80% [1 gitlab-ee 811 MB/811 MB 100%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 80% [1 gitlab-ee 811 MB/811 MB 100%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 80% [1 gitlab-ee 811 MB/811 MB 100%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 80% [1 gitlab-ee 811 MB/811 MB 100%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 80% [1 gitlab-ee 811 MB/811 MB 100%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 80% [1 gitlab-ee 811 MB/811 MB 100%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 80% [1 gitlab-ee 811 MB/811 MB 100%]
module.gitlab.aws_instance.gitlab[0]: Still creating... [1m20s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 80% [1 gitlab-ee 811 MB/811 MB 100%]
module.gitlab.aws_instance.gitlab[0] (remote-exec): 100% [Working]             68.7 MB/s 0s
module.gitlab.aws_instance.gitlab[0] (remote-exec): Fetched 811 MB in 17s (47.7 MB/s)
module.squidproxy.aws_instance.squidproxy[0]: Still creating... [1m20s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Selecting previously unselected package gitlab-ee.
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ...
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 5%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 10%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 15%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 20%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 25%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 30%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 35%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 40%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 45%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 50%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 55%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 60%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 65%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 70%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 75%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 80%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 85%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 90%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 95%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 100%
module.gitlab.aws_instance.gitlab[0] (remote-exec): (Reading database ... 56538 files and directories currently installed.)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Preparing to unpack .../gitlab-ee_12.6.2-ee.0_amd64.deb ...
module.gitlab.aws_instance.gitlab[0] (remote-exec): Unpacking gitlab-ee (12.6.2-ee.0) ...
module.squidproxy.aws_instance.squidproxy[0]: Creation complete after 1m28s [id=i-02f045d8b456a5cfe]
module.gitlab.aws_ins

module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-lxd-inotify.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.inotify.max_user_instances = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-magic-sysrq.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sysrq = 176
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-network-security.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.default.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.tcp_syncookies = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ptrace.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.yama.ptrace_scope = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-zeropage.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 vm.mmap_min_addr = 65536
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /usr/lib/sysctl.d/50-default.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.promote_secondaries = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.core.default_qdisc = fq_codel
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-cloudimg-ipv6.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute sysctl -e --system
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/etc/sysctl.d/90-omnibus-gitlab-kernel.shmmax.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /etc/sysctl.d/90-omnibus-gitlab-kernel.shmmax.conf to /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.shmmax.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf kernel.shmmax] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] * Applying /etc/sysctl.d/10-console-messages.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.printk = 4 4 1 7
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ipv6-privacy.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-kernel-hardening.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.kptr_restrict = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-link-restrictions.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_hardlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_symlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-lxd-inotify.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.inotify.max_user_instances = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-magic-sysrq.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sysrq = 176
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-network-security.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.default.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.tcp_syncookies = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ptrace.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.yama.ptrace_scope = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-zeropage.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 vm.mmap_min_addr = 65536
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /usr/lib/sysctl.d/50-default.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.promote_secondaries = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.core.default_qdisc = fq_codel
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmmax.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmmax = 17179869184
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-cloudimg-ipv6.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute sysctl -e --system
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf kernel.shmmax] action nothing (skipped due to action :nothing)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * gitlab_sysctl[kernel.shmall] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[create /etc/sysctl.d for kernel.shmall] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[create /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.shmall.conf kernel.shmall] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.shmall.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.shmall.conf from none to 6d765d
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.shmall.conf	2020-01-03 12:37:13.579929701 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/embedded/etc/.chef-90-omnibus-gitlab-kernel20200103-12696-1wcw9s4.shmall.conf	2020-01-03 12:37:13.579929701 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +kernel.shmall = 4194304
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf kernel.shmall] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] * Applying /etc/sysctl.d/10-console-messages.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.printk = 4 4 1 7
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ipv6-privacy.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-kernel-hardening.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.kptr_restrict = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-link-restrictions.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_hardlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_symlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-lxd-inotify.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.inotify.max_user_instances = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-magic-sysrq.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sysrq = 176
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-network-security.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.default.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.tcp_syncookies = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ptrace.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.yama.ptrace_scope = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-zeropage.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 vm.mmap_min_addr = 65536
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /usr/lib/sysctl.d/50-default.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.promote_secondaries = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.core.default_qdisc = fq_codel
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmmax.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmmax = 17179869184
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-cloudimg-ipv6.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute sysctl -e --system
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/etc/sysctl.d/90-omnibus-gitlab-kernel.shmall.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /etc/sysctl.d/90-omnibus-gitlab-kernel.shmall.conf to /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.shmall.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf kernel.shmall] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] * Applying /etc/sysctl.d/10-console-messages.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.printk = 4 4 1 7
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ipv6-privacy.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-kernel-hardening.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.kptr_restrict = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-link-restrictions.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_hardlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_symlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-lxd-inotify.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.inotify.max_user_instances = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-magic-sysrq.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sysrq = 176
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-network-security.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.default.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.tcp_syncookies = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ptrace.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.yama.ptrace_scope = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-zeropage.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 vm.mmap_min_addr = 65536
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /usr/lib/sysctl.d/50-default.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.promote_secondaries = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.core.default_qdisc = fq_codel
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmall.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmall = 4194304
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmmax.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmmax = 17179869184
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-cloudimg-ipv6.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute sysctl -e --system
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf kernel.shmall] action nothing (skipped due to action :nothing)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * gitlab_sysctl[kernel.sem] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[create /etc/sysctl.d for kernel.sem] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[create /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.sem.conf kernel.sem] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.sem.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.sem.conf from none to 09a346
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.sem.conf	2020-01-03 12:37:13.631929708 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/embedded/etc/.chef-90-omnibus-gitlab-kernel20200103-12696-twjgvv.sem.conf	2020-01-03 12:37:13.631929708 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +kernel.sem = 250 32000 32 262
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf kernel.sem] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] * Applying /etc/sysctl.d/10-console-messages.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.printk = 4 4 1 7
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ipv6-privacy.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-kernel-hardening.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.kptr_restrict = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-link-restrictions.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_hardlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_symlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-lxd-inotify.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.inotify.max_user_instances = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-magic-sysrq.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sysrq = 176
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-network-security.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.default.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.tcp_syncookies = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ptrace.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.yama.ptrace_scope = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-zeropage.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 vm.mmap_min_addr = 65536
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /usr/lib/sysctl.d/50-default.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.promote_secondaries = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.core.default_qdisc = fq_codel
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmall.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmall = 4194304
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmmax.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmmax = 17179869184
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-cloudimg-ipv6.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute sysctl -e --system
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/etc/sysctl.d/90-omnibus-gitlab-kernel.sem.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /etc/sysctl.d/90-omnibus-gitlab-kernel.sem.conf to /opt/gitlab/embedded/etc/90-omnibus-gitlab-kernel.sem.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf kernel.sem] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] * Applying /etc/sysctl.d/10-console-messages.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.printk = 4 4 1 7
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ipv6-privacy.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-kernel-hardening.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.kptr_restrict = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-link-restrictions.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_hardlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_symlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-lxd-inotify.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.inotify.max_user_instances = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-magic-sysrq.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sysrq = 176
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-network-security.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.default.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.tcp_syncookies = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ptrace.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.yama.ptrace_scope = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-zeropage.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 vm.mmap_min_addr = 65536
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /usr/lib/sysctl.d/50-default.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.promote_secondaries = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.core.default_qdisc = fq_codel
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.sem.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sem = 250 32000 32 262
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmall.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmall = 4194304
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmmax.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmmax = 17179869184
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-cloudimg-ipv6.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute sysctl -e --system
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf kernel.sem] action nothing (skipped due to action :nothing)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/embedded/bin/initdb -D /var/opt/gitlab/postgresql/data -E UTF8] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] The files belonging to this database system will be owned by user "gitlab-psql".
module.gitlab.aws_instance.gitlab[0] (remote-exec):               This user must also own the server process.

module.gitlab.aws_instance.gitlab[0] (remote-exec):               The database cluster will be initialized with locale "C.UTF-8".
module.gitlab.aws_instance.gitlab[0] (remote-exec):               The default text search configuration will be set to "english".

module.gitlab.aws_instance.gitlab[0] (remote-exec):               Data page checksums are disabled.

module.gitlab.aws_instance.gitlab[0] (remote-exec):               fixing permissions on existing directory /var/opt/gitlab/postgresql/data ... ok
module.gitlab.aws_instance.gitlab[0] (remote-exec):               creating subdirectories ... ok
module.gitlab.aws_instance.gitlab[0] (remote-exec):               selecting default max_connections ... 100
module.gitlab.aws_instance.gitlab[0] (remote-exec):               selecting default shared_buffers ... 128MB
module.gitlab.aws_instance.gitlab[0] (remote-exec):               selecting default timezone ... Etc/UTC
module.gitlab.aws_instance.gitlab[0] (remote-exec):               selecting dynamic shared memory implementation ... posix
module.gitlab.aws_instance.gitlab[0] (remote-exec):               creating configuration files ... ok
module.gitlab.aws_instance.gitlab[0] (remote-exec):               running bootstrap script ...
module.gitlab.aws_instance.gitlab[0] (remote-exec): ok
module.gitlab.aws_instance.gitlab[0] (remote-exec):               performing post-bootstrap initialization ...
module.gitlab.aws_instance.gitlab[0] (remote-exec): ok
module.gitlab.aws_instance.gitlab[0] (remote-exec):               syncing data to disk ...
module.gitlab.aws_instance.gitlab[0] (remote-exec): ok

module.gitlab.aws_instance.gitlab[0] (remote-exec):               Success. You can now start the database server using:

module.gitlab.aws_instance.gitlab[0] (remote-exec):                   /opt/gitlab/embedded/bin/pg_ctl -D /var/opt/gitlab/postgresql/data -l logfile start


module.gitlab.aws_instance.gitlab[0] (remote-exec):               WARNING: enabling "trust" authentication for local connections
module.gitlab.aws_instance.gitlab[0] (remote-exec):               You can change this by editing pg_hba.conf or using the option -A, or
module.gitlab.aws_instance.gitlab[0] (remote-exec):               --auth-local and --auth-host, the next time you run initdb.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/embedded/bin/initdb -D /var/opt/gitlab/postgresql/data -E UTF8
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[/var/opt/gitlab/postgresql/data/server.crt] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/postgresql/data/server.crt
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/postgresql/data/server.crt from none to caf314
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - suppressed sensitive resource
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0400'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[/var/opt/gitlab/postgresql/data/server.key] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/postgresql/data/server.key
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/postgresql/data/server.key from none to 7d5a0e
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - suppressed sensitive resource
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0400'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * postgresql_config[gitlab] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/opt/gitlab/postgresql/data/postgresql.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/opt/gitlab/postgresql/data/postgresql.conf from 58e6e9 to 309502
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/opt/gitlab/postgresql/data/postgresql.conf	2020-01-03 12:37:13.755929725 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/opt/gitlab/postgresql/data/.chef-postgresql20200103-12696-mmrhz2.conf	2020-01-03 12:37:14.595929834 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1,3 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# This file is managed by gitlab-ctl. Manual changes will be
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# and run `sudo gitlab-ctl reconfigure`.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # -----------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # PostgreSQL configuration file
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # -----------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -16,9 +20,9 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # This file is read on server startup and when the server receives a SIGHUP
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # signal.  If you edit the file on a running system, you have to SIGHUP the
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# server for the changes to take effect, run "pg_ctl reload", or execute
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# "SELECT pg_reload_conf()".  Some parameters, which are marked below,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# require a server shutdown and restart to take effect.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# server for the changes to take effect, or use "pg_ctl reload".  Some
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# parameters, which are marked below, require a server shutdown and restart to
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# take effect.
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # Any parameter can also be given as a command-line option to the server, e.g.,
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # "postgres -c log_connections=on".  Some parameters can be changed at run time
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -27,7 +31,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # Memory units:  kB = kilobytes        Time units:  ms  = milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #                MB = megabytes                     s   = seconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #                GB = gigabytes                     min = minutes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#                TB = terabytes                     h   = hours
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#                                                   h   = hours
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #                                                   d   = days
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -38,16 +42,16 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # The default values of these variables are driven from the -D command-line
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # option or PGDATA environment variable, represented here as ConfigDir.
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#data_directory = 'ConfigDir'		# use data in another directory
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#hba_file = 'ConfigDir/pg_hba.conf'	# host-based authentication file
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ident_file = 'ConfigDir/pg_ident.conf'	# ident configuration file
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#data_directory = 'ConfigDir'   # use data in another directory
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#hba_file = 'ConfigDir/pg_hba.conf' # host-based authentication file
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#ident_file = 'ConfigDir/pg_ident.conf' # ident configuration file
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # If external_pid_file is not explicitly set, no extra PID file is written.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#external_pid_file = ''			# write an extra PID file
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#external_pid_file = '(none)'   # write an extra PID file
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -56,52 +60,57 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Connection Settings -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#listen_addresses = 'localhost'		# what IP address(es) to listen on;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# comma-separated list of addresses;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# defaults to 'localhost'; use '*' for all
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#port = 5432				# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -max_connections = 100			# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#superuser_reserved_connections = 3	# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#unix_socket_directories = '/tmp'	# comma-separated list of directories
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#unix_socket_group = ''			# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#unix_socket_permissions = 0777		# begin with 0 to use octal notation
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#bonjour = off				# advertise server via Bonjour
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#bonjour_name = ''			# defaults to the computer name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +listen_addresses = ''    # what IP address(es) to listen on;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # comma-separated list of addresses;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # defaults to 'localhost', '*' = all
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +port = 5432        # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_connections = 200      # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Note:  Increasing max_connections costs ~400 bytes of shared memory per
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# connection slot, plus lock space (see max_locks_per_transaction).
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#superuser_reserved_connections = 3 # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +unix_socket_directories = '/var/opt/gitlab/postgresql'   # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#unix_socket_group = ''     # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#unix_socket_permissions = 0777   # begin with 0 to use octal notation
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#bonjour = off        # advertise server via Bonjour
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#bonjour_name = ''      # defaults to the computer name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Security and Authentication -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#authentication_timeout = 1min		# 1s-600s
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ssl = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL' # allowed SSL ciphers
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ssl_prefer_server_ciphers = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ssl_ecdh_curve = 'prime256v1'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ssl_dh_params_file = ''
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ssl_cert_file = 'server.crt'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ssl_key_file = 'server.key'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ssl_ca_file = ''
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#ssl_crl_file = ''
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#password_encryption = md5		# md5 or scram-sha-256
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#authentication_timeout = 1min    # 1s-600s
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# change requires restart
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +ssl = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# allowed SSL ciphers
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL:!SSLv3:!TLSv1'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +ssl_cert_file = 'server.crt'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +ssl_key_file = 'server.key'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +ssl_ca_file = '/opt/gitlab/embedded/ssl/certs/cacert.pem'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#ssl_renegotiation_limit = 512MB  # amount of data between renegotiations
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#password_encryption = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #db_user_namespace = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#row_security = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# GSSAPI using Kerberos
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Kerberos and GSSAPI
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #krb_server_keyfile = ''
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#krb_srvname = 'postgres'   # (Kerberos only)
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #krb_caseins_users = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - TCP Keepalives -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # see "man 7 tcp" for details
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#tcp_keepalives_idle = 0		# TCP_KEEPIDLE, in seconds;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# 0 selects the system default
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#tcp_keepalives_interval = 0		# TCP_KEEPINTVL, in seconds;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# 0 selects the system default
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#tcp_keepalives_count = 0		# TCP_KEEPCNT;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# 0 selects the system default
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#tcp_keepalives_idle = 0    # TCP_KEEPIDLE, in seconds;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # 0 selects the system default
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#tcp_keepalives_interval = 0    # TCP_KEEPINTVL, in seconds;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # 0 selects the system default
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#tcp_keepalives_count = 0   # TCP_KEEPCNT;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # 0 selects the system default
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -110,65 +119,40 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Memory -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -shared_buffers = 128MB			# min 128kB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#huge_pages = try			# on, off, or try
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#temp_buffers = 8MB			# min 800kB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_prepared_transactions = 0		# zero disables the feature
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# Caution: it is not advisable to set max_prepared_transactions nonzero unless
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# you actively intend to use prepared transactions.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#work_mem = 4MB				# min 64kB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#maintenance_work_mem = 64MB		# min 1MB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#replacement_sort_tuples = 150000	# limits use of replacement selection sort
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_work_mem = -1		# min 1MB, or -1 to use maintenance_work_mem
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_stack_depth = 2MB			# min 100kB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -dynamic_shared_memory_type = posix	# the default is the first option
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# supported by the operating system:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   posix
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   sysv
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   windows
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   mmap
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# use none to disable dynamic shared memory
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +shared_buffers = 1920MB # min 128kB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#temp_buffers = 8MB     # min 800kB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#max_prepared_transactions = 0    # zero disables the feature
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Note:  Increasing max_prepared_transactions costs ~600 bytes of shared memory
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# per transaction slot, plus lock space (see max_locks_per_transaction).
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# It is not advisable to set max_prepared_transactions nonzero unless you
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# actively intend to use prepared transactions.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#max_stack_depth = 2MB      # min 100kB
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# - Disk -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#temp_file_limit = -1			# limits per-process temp file space
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# in kB, or -1 for no limit
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Kernel Resource Usage -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_files_per_process = 1000		# min 25
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#shared_preload_libraries = ''		# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#max_files_per_process = 1000   # min 25
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +shared_preload_libraries = ''    # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Cost-Based Vacuum Delay -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#vacuum_cost_delay = 0			# 0-100 milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#vacuum_cost_page_hit = 1		# 0-10000 credits
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#vacuum_cost_page_miss = 10		# 0-10000 credits
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#vacuum_cost_page_dirty = 20		# 0-10000 credits
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#vacuum_cost_limit = 200		# 1-10000 credits
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#vacuum_cost_delay = 0ms    # 0-100 milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#vacuum_cost_page_hit = 1   # 0-10000 credits
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#vacuum_cost_page_miss = 10   # 0-10000 credits
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#vacuum_cost_page_dirty = 20    # 0-10000 credits
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#vacuum_cost_limit = 200    # 1-10000 credits
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Background Writer -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#bgwriter_delay = 200ms			# 10-10000ms between rounds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#bgwriter_lru_maxpages = 100		# 0-1000 max buffers written/round
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#bgwriter_lru_multiplier = 2.0		# 0-10.0 multiplier on buffers scanned/round
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#bgwriter_flush_after = 512kB		# measured in pages, 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#bgwriter_delay = 200ms     # 10-10000ms between rounds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#bgwriter_lru_maxpages = 100    # 0-1000 max buffers written/round
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#bgwriter_lru_multiplier = 2.0    # 0-10.0 multipler on buffers scanned/round
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Asynchronous Behavior -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#effective_io_concurrency = 1		# 1-1000; 0 disables prefetching
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_worker_processes = 8		# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_parallel_workers_per_gather = 2	# taken from max_parallel_workers
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_parallel_workers = 8		# maximum number of max_worker_processes that
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# can be used in parallel queries
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#old_snapshot_threshold = -1		# 1min-60d; -1 disables; 0 is immediate
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#backend_flush_after = 0		# measured in pages, 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#effective_io_concurrency = 1   # 1-1000. 0 disables prefetching
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -177,112 +161,62 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Settings -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_level = replica			# minimal, replica, or logical
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#fsync = on				# flush data to disk for crash safety
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (turning this off can cause
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# unrecoverable data corruption)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#synchronous_commit = on		# synchronization level;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# off, local, remote_write, remote_apply, or on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_sync_method = fsync		# the default is the first option
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# supported by the operating system:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   open_datasync
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   fdatasync (default on Linux)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   fsync
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   fsync_writethrough
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   open_sync
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#full_page_writes = on			# recover from partial page writes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_compression = off			# enable compression of full-page writes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_log_hints = off			# also do full page writes of non-critical updates
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_buffers = -1			# min 32kB, -1 sets based on shared_buffers
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_writer_delay = 200ms		# 1-10000 milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_writer_flush_after = 1MB		# measured in pages, 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +wal_level = minimal
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#fsync = on       # turns forced synchronization on or off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#wal_sync_method = fsync    # the default is the first option
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # supported by the operating system:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   open_datasync
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   fdatasync (default on Linux)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   fsync
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   fsync_writethrough
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   open_sync
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#full_page_writes = on      # recover from partial page writes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +wal_buffers = -1 # -1     # min 32kB, -1 sets based on shared_buffers
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#wal_writer_delay = 200ms   # 1-10000 milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#commit_delay = 0			# range 0-100000, in microseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#commit_siblings = 5			# range 1-1000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#commit_delay = 0     # range 0-100000, in microseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#commit_siblings = 5      # range 1-1000
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# - Checkpoints -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +min_wal_size = 80MB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_wal_size = 1GB
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#checkpoint_timeout = 5min		# range 30s-1d
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_wal_size = 1GB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#min_wal_size = 80MB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#checkpoint_completion_target = 0.5	# checkpoint target duration, 0.0 - 1.0
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#checkpoint_flush_after = 256kB		# measured in pages, 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#checkpoint_warning = 30s		# 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# The number of replication slots to reserve.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_replication_slots = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Archiving -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#archive_mode = off		# enables archiving; off, on, or always
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#archive_command = ''		# command to use to archive a logfile segment
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# placeholders: %p = path of file to archive
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				#               %f = file name only
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# e.g. 'test ! -f /mnt/server/archivedir/%f && cp %p /mnt/server/archivedir/%f'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#archive_timeout = 0		# force a logfile segment switch after this
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# number of seconds; 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +archive_mode = off   # allows archiving to be done
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +        # (change requires restart, also requires 'wal_level' of 'hot_standby' OR 'replica')
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # REPLICATION
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# - Sending Server(s) -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# Set these on the master and on any standby that will send replication data.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_wal_senders = 10		# max number of walsender processes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_keep_segments = 0		# in logfile segments, 16MB each; 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_sender_timeout = 60s	# in milliseconds; 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_replication_slots = 10	# max number of replication slots
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#track_commit_timestamp = off	# collect timestamp of transaction commit
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Master Server -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# These settings are ignored on a standby server.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# These settings are ignored on a standby server
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#synchronous_standby_names = ''	# standby servers that provide sync rep
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# method to choose sync standbys, number of sync standbys,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# and comma-separated list of application_name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -				# from standby(s); '*' = all
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#vacuum_defer_cleanup_age = 0	# number of xacts by which cleanup is delayed
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_wal_senders = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +        # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#wal_sender_delay = 1s    # walsender cycle time, 1-10000 milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#vacuum_defer_cleanup_age = 0 # number of xacts by which cleanup is delayed
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#replication_timeout = 60s  # in milliseconds; 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#synchronous_standby_names = '' # standby servers that provide sync rep
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +        # comma-separated list of application_name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +        # from standby(s); '*' = all
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Standby Servers -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# These settings are ignored on a master server.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# These settings are ignored on a master server
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#hot_standby = on			# "off" disallows queries during recovery
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_standby_archive_delay = 30s	# max delay before canceling queries
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# when reading WAL from archive;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# -1 allows indefinite delay
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_standby_streaming_delay = 30s	# max delay before canceling queries
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# when reading streaming WAL;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# -1 allows indefinite delay
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_receiver_status_interval = 10s	# send replies at least this often
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#hot_standby_feedback = off		# send info from standby to prevent
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# query conflicts
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_receiver_timeout = 60s		# time that receiver waits for
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# communication from master
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# in milliseconds; 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#wal_retrieve_retry_interval = 5s	# time to wait before retrying to
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# retrieve WAL after a failed attempt
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +hot_standby = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#wal_receiver_status_interval = 10s # send replies at least this often
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# - Subscribers -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# These settings are ignored on a publisher.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_logical_replication_workers = 4	# taken from max_worker_processes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_sync_workers_per_subscription = 2	# taken from max_logical_replication_workers
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # QUERY TUNING
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -293,7 +227,6 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #enable_hashagg = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #enable_hashjoin = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #enable_indexscan = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#enable_indexonlyscan = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #enable_material = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #enable_mergejoin = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #enable_nestloop = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -303,36 +236,28 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Planner Cost Constants -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#seq_page_cost = 1.0			# measured on an arbitrary scale
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#random_page_cost = 4.0			# same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#cpu_tuple_cost = 0.01			# same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#cpu_index_tuple_cost = 0.005		# same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#cpu_operator_cost = 0.0025		# same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#parallel_tuple_cost = 0.1		# same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#parallel_setup_cost = 1000.0	# same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#min_parallel_table_scan_size = 8MB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#min_parallel_index_scan_size = 512kB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#effective_cache_size = 4GB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#cpu_tuple_cost = 0.01      # same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#cpu_index_tuple_cost = 0.005   # same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#cpu_operator_cost = 0.0025   # same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Genetic Query Optimizer -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #geqo = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #geqo_threshold = 12
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#geqo_effort = 5			# range 1-10
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#geqo_pool_size = 0			# selects default based on effort
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#geqo_generations = 0			# selects default based on effort
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#geqo_selection_bias = 2.0		# range 1.5-2.0
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#geqo_seed = 0.0			# range 0.0-1.0
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#geqo_effort = 5      # range 1-10
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#geqo_pool_size = 0     # selects default based on effort
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#geqo_generations = 0     # selects default based on effort
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#geqo_selection_bias = 2.0    # range 1.5-2.0
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#geqo_seed = 0.0      # range 0.0-1.0
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Other Planner Options -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#default_statistics_target = 100	# range 1-10000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#constraint_exclusion = partition	# on, off, or partition
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#cursor_tuple_fraction = 0.1		# range 0.0-1.0
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#default_statistics_target = 100  # range 1-10000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#constraint_exclusion = partition # on, off, or partition
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#cursor_tuple_fraction = 0.1    # range 0.0-1.0
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #from_collapse_limit = 8
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#join_collapse_limit = 8		# 1 disables collapsing of explicit
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# JOIN clauses
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#force_parallel_mode = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#join_collapse_limit = 8    # 1 disables collapsing of explicit
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # JOIN clauses
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -341,133 +266,105 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Where to Log -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_destination = 'stderr'		# Valid values are combinations of
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# stderr, csvlog, syslog, and eventlog,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# depending on platform.  csvlog
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# requires logging_collector to be on.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_destination = 'stderr'   # Valid values are combinations of
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # stderr, csvlog, syslog, and eventlog,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # depending on platform.  csvlog
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # requires logging_collector to be on.
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # This is used when logging to stderr:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#logging_collector = off		# Enable capturing of stderr and csvlog
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# into log files. Required to be on for
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# csvlogs.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#logging_collector = off    # Enable capturing of stderr and csvlog
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # into log files. Required to be on for
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # csvlogs.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # These are only used if logging_collector is on:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_directory = 'log'			# directory where log files are written,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# can be absolute or relative to PGDATA
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'	# log file name pattern,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# can include strftime() escapes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_file_mode = 0600			# creation mode for log files,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# begin with 0 to use octal notation
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_truncate_on_rotation = off		# If on, an existing log file with the
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# same name as the new log file will be
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# truncated rather than appended to.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# But such truncation only occurs on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# time-driven rotation, not on restarts
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# or size-driven rotation.  Default is
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# off, meaning append to existing files
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# in all cases.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_rotation_age = 1d			# Automatic rotation of logfiles will
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# happen after that time.  0 disables.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_rotation_size = 10MB		# Automatic rotation of logfiles will
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# happen after that much log output.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# 0 disables.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_directory = 'pg_log'   # directory where log files are written,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # can be absolute or relative to PGDATA
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'  # log file name pattern,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # can include strftime() escapes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_file_mode = 0600     # creation mode for log files,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # begin with 0 to use octal notation
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_truncate_on_rotation = off   # If on, an existing log file with the
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # same name as the new log file will be
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # truncated rather than appended to.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # But such truncation only occurs on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # time-driven rotation, not on restarts
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # or size-driven rotation.  Default is
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # off, meaning append to existing files
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # in all cases.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_rotation_age = 1d      # Automatic rotation of logfiles will
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # happen after that time.  0 disables.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_rotation_size = 10MB   # Automatic rotation of logfiles will
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # happen after that much log output.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # 0 disables.
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # These are relevant when logging to syslog:
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #syslog_facility = 'LOCAL0'
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #syslog_ident = 'postgres'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#syslog_sequence_numbers = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#syslog_split_messages = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# This is only relevant when logging to eventlog (win32):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#event_source = 'PostgreSQL'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#silent_mode = off      # Run server silently.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # DO NOT USE without syslog or
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # logging_collector
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - When to Log -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_min_messages = warning		# values in order of decreasing detail:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug5
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug4
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug3
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug2
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   info
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   notice
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   warning
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   error
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   fatal
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   panic
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#client_min_messages = notice   # values in order of decreasing detail:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug5
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug4
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug3
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug2
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   notice
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   warning
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   error
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_min_error_statement = error	# values in order of decreasing detail:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug5
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug4
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug3
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug2
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   info
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   notice
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   warning
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   error
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   fatal
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   panic (effectively off)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_min_messages = warning   # values in order of decreasing detail:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug5
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug4
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug3
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug2
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   info
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   notice
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   warning
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   error
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   fatal
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   panic
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_min_duration_statement = -1	# -1 is disabled, 0 logs all statements
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# and their durations, > 0 logs only
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# statements running at least this number
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# of milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_min_error_statement = error  # values in order of decreasing detail:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug5
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug4
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug3
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug2
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   debug1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   info
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   notice
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   warning
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   error
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   fatal
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   panic (effectively off)
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - What to Log -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #debug_print_parse = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #debug_print_rewritten = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #debug_print_plan = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #debug_pretty_print = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_checkpoints = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #log_connections = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #log_disconnections = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #log_duration = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_error_verbosity = default		# terse, default, or verbose messages
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_error_verbosity = default    # terse, default, or verbose messages
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #log_hostname = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_line_prefix = '%m [%p] '		# special values:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %a = application name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %u = user name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %d = database name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %r = remote host and port
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %h = remote host
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %p = process ID
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %t = timestamp without milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %m = timestamp with milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %n = timestamp with milliseconds (as a Unix epoch)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %i = command tag
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %e = SQL state
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %c = session ID
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %l = session line number
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %s = session start timestamp
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %v = virtual transaction ID
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %x = transaction ID (0 if none)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %q = stop here in non-session
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#        processes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   %% = '%'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# e.g. '<%u%%%d> '
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_lock_waits = off			# log lock waits >= deadlock_timeout
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_statement = 'none'			# none, ddl, mod, all
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_replication_commands = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_temp_files = -1			# log temporary files equal or larger
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# than the specified size in kilobytes;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# -1 disables, 0 logs all temp files
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -log_timezone = 'Etc/UTC'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_lock_waits = off     # log lock waits >= deadlock_timeout
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_statement = 'none'     # none, ddl, mod, all
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#log_timezone = '(defaults to server environment setting)'
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# - Process Title -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#cluster_name = ''			# added to process titles if nonempty
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#update_process_title = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # RUNTIME STATISTICS
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -476,9 +373,9 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #track_activities = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #track_counts = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#track_io_timing = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#track_functions = none			# none, pl, all
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#track_activity_query_size = 1024	# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#track_functions = none     # none, pl, all
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +track_activity_query_size = 1024 # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#update_process_title = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #stats_temp_directory = 'pg_stat_tmp'
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -494,103 +391,50 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # AUTOVACUUM PARAMETERS
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum = on			# Enable autovacuum subprocess?  'on'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# requires track_counts to also be on.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#log_autovacuum_min_duration = -1	# -1 disables, 0 logs all actions and
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# their durations, > 0 logs only
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# actions running at least this number
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# of milliseconds.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_max_workers = 3		# max number of autovacuum subprocesses
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_naptime = 1min		# time between autovacuum runs
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_vacuum_threshold = 50	# min number of row updates before
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# vacuum
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_analyze_threshold = 50	# min number of row updates before
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# analyze
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_vacuum_scale_factor = 0.2	# fraction of table size before vacuum
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_analyze_scale_factor = 0.1	# fraction of table size before analyze
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_freeze_max_age = 200000000	# maximum XID age before forced vacuum
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_multixact_freeze_max_age = 400000000	# maximum multixact age
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# before forced vacuum
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_vacuum_cost_delay = 20ms	# default vacuum cost delay for
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# autovacuum, in milliseconds;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# -1 means use vacuum_cost_delay
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#autovacuum_vacuum_cost_limit = -1	# default vacuum cost limit for
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# autovacuum, -1 means use
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# vacuum_cost_limit
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum_max_workers = 3 # max number of autovacuum subprocesses
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum_freeze_max_age = 200000000  # maximum XID age before forced vacuum
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # CLIENT CONNECTION DEFAULTS
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Statement Behavior -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#client_min_messages = notice		# values in order of decreasing detail:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug5
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug4
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug3
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug2
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   debug1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   notice
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   warning
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   error
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#search_path = '"$user", public'	# schema names
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#default_tablespace = ''		# a tablespace name, '' uses the default
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#temp_tablespaces = ''			# a list of tablespace names, '' uses
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# only default tablespace
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#search_path = '"$user",public'   # schema names
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#default_tablespace = ''    # a tablespace name, '' uses the default
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#temp_tablespaces = ''      # a list of tablespace names, '' uses
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # only default tablespace
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #check_function_bodies = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #default_transaction_isolation = 'read committed'
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #default_transaction_read_only = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #default_transaction_deferrable = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #session_replication_role = 'origin'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#statement_timeout = 0			# in milliseconds, 0 is disabled
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#lock_timeout = 0			# in milliseconds, 0 is disabled
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#idle_in_transaction_session_timeout = 0# in milliseconds, 0 is disabled
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #vacuum_freeze_min_age = 50000000
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #vacuum_freeze_table_age = 150000000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#vacuum_multixact_freeze_min_age = 5000000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#vacuum_multixact_freeze_table_age = 150000000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#bytea_output = 'hex'			# hex, escape
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#bytea_output = 'hex'     # hex, escape
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #xmlbinary = 'base64'
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #xmloption = 'content'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#gin_fuzzy_search_limit = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#gin_pending_list_limit = 4MB
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Locale and Formatting -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -datestyle = 'iso, mdy'
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #intervalstyle = 'postgres'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -timezone = 'Etc/UTC'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#timezone = '(defaults to server environment setting)'
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #timezone_abbreviations = 'Default'     # Select the set of available time zone
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# abbreviations.  Currently, there are
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   Default
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   Australia (historical usage)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#   India
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# You can create your own file in
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# share/timezonesets/.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#extra_float_digits = 0			# min -15, max 3
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#client_encoding = sql_ascii		# actually, defaults to database
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# encoding
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # abbreviations.  Currently, there are
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   Default
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   Australia
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   India
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # You can create your own file in
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # share/timezonesets/.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#extra_float_digits = 0     # min -15, max 3
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#client_encoding = sql_ascii    # actually, defaults to database
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # encoding
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# These settings are initialized by initdb, but they can be changed.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -lc_messages = 'C.UTF-8'			# locale for system error message
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# strings
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -lc_monetary = 'C.UTF-8'			# locale for monetary formatting
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -lc_numeric = 'C.UTF-8'			# locale for number formatting
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -lc_time = 'C.UTF-8'				# locale for time formatting
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# default configuration for text search
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -default_text_search_config = 'pg_catalog.english'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Other Defaults -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #dynamic_library_path = '$libdir'
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #local_preload_libraries = ''
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#session_preload_libraries = ''
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -598,16 +442,14 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #deadlock_timeout = 1s
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_locks_per_transaction = 64		# min 10
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_pred_locks_per_transaction = 64	# min 10
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_pred_locks_per_relation = -2	# negative values mean
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (max_pred_locks_per_transaction
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					#  / -max_pred_locks_per_relation) - 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#max_pred_locks_per_page = 2            # min 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_locks_per_transaction = 128   # min 10
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Note:  Each lock table slot uses ~270 bytes of shared memory, and there are
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# max_locks_per_transaction * (max_connections + max_prepared_transactions)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# lock table slots.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#max_pred_locks_per_transaction = 64  # min 10
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # VERSION/PLATFORM COMPATIBILITY
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -615,12 +457,12 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # - Previous PostgreSQL Versions -
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #array_nulls = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#backslash_quote = safe_encoding	# on, off, or safe_encoding
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#backslash_quote = safe_encoding  # on, off, or safe_encoding
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #default_with_oids = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #escape_string_warning = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #lo_compat_privileges = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#operator_precedence_warning = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #quote_all_identifiers = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#sql_inheritance = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #standard_conforming_strings = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #synchronize_seqscans = on
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -633,29 +475,15 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # ERROR HANDLING
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#exit_on_error = off			# terminate session on any error?
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#restart_after_crash = on		# reinitialize after backend crash?
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#data_sync_retry = off			# retry or panic on failure to fsync
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# data?
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# (change requires restart)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#exit_on_error = off        # terminate session on any error?
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#restart_after_crash = on     # reinitialize after backend crash?
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# CONFIG FILE INCLUDES
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# These options allow settings to be loaded from files other than the
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# default postgresql.conf.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#include_dir = ''			# include files ending in '.conf' from
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -					# a directory, e.g., 'conf.d'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#include_if_exists = ''			# include file only if it exists
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#include = ''				# include file
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # CUSTOMIZED OPTIONS
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #------------------------------------------------------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# Add settings for extensions here
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#custom_variable_classes = ''   # list of custom variable class names
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +include 'runtime.conf'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '0600' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/opt/gitlab/postgresql/data/runtime.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/opt/gitlab/postgresql/data/runtime.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/opt/gitlab/postgresql/data/runtime.conf from none to 969d4d
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/opt/gitlab/postgresql/data/runtime.conf	2020-01-03 12:37:14.643929841 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/opt/gitlab/postgresql/data/.chef-runtime20200103-12696-127oxq5.conf	2020-01-03 12:37:14.643929841 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,132 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# This file is managed by gitlab-ctl. Manual changes will be
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# and run `sudo gitlab-ctl reconfigure`.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Changing variables in this file should only require a reload of PostgreSQL
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# As the gitlab-psql user, run:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# /opt/gitlab/embedded/bin/pg_ctl reload -D /var/opt/gitlab/postgresql/data
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +work_mem = 16MB				# min 64kB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +maintenance_work_mem = 16MB # 16MB    # min 1MB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +synchronous_commit = on # synchronization level; on, off, or local
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +synchronous_standby_names = ''
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# - Checkpoints -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +min_wal_size = 80MB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_wal_size = 1GB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +checkpoint_timeout = 5min		# range 30s-1h, default 5min
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +checkpoint_completion_target = 0.9	# checkpoint target duration, 0.0 - 1.0, default 0.5
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +checkpoint_warning = 30s		# 0 disables, default 30s
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# - Archiving -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +archive_command = ''   # command to use to archive a logfile segment
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +archive_timeout = 0    # force a logfile segment switch after this
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +        # number of seconds; 0 disables
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# - Replication
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +wal_keep_segments = 10
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_standby_archive_delay = 30s # max delay before canceling queries
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # when reading WAL from archive;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # -1 allows indefinite delay
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_standby_streaming_delay = 30s # max delay before canceling queries
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # when reading streaming WAL;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # -1 allows indefinite delay
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +hot_standby_feedback = off   # send info from standby to prevent
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # query conflicts
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# - Planner Cost Constants -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#seq_page_cost = 1.0      # measured on an arbitrary scale
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +random_page_cost = 2.0     # same scale as above
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +effective_cache_size = 3840MB # Default 128MB
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +log_min_duration_statement = -1  # -1 is disabled, 0 logs all statements
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # and their durations, > 0 logs only
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # statements running at least this number
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # of milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +log_checkpoints = off
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +log_line_prefix = '' # default '', special values:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %a = application name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %u = user name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %d = database name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %r = remote host and port
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %h = remote host
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %p = process ID
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %t = timestamp without milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %m = timestamp with milliseconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %i = command tag
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %e = SQL state
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %c = session ID
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %l = session line number
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %s = session start timestamp
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %v = virtual transaction ID
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %x = transaction ID (0 if none)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %q = stop here in non-session
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #        processes
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          #   %% = '%'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +log_temp_files = -1      # log temporary files equal or larger
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # than the specified size in kilobytes;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # -1 disables, 0 logs all temp files
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# - Autovacuum parameters -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum = on # Enable autovacuum subprocess?  'on'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # requires track_counts to also be on.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +log_autovacuum_min_duration = -1 # -1 disables, 0 logs all actions and
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # their durations, > 0 logs only
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # actions running at least this number
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # of milliseconds.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum_naptime = 1min # time between autovacuum runs
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum_vacuum_threshold = 50 # min number of row updates before
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # vacuum
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum_analyze_threshold = 50 # min number of row updates before
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # analyze
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum_vacuum_scale_factor = 0.02 # fraction of table size before vacuum
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum_analyze_scale_factor = 0.01 # fraction of table size before analyze
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum_vacuum_cost_delay = 20ms # default vacuum cost delay for
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # autovacuum, in milliseconds;
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # -1 means use vacuum_cost_delay
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +autovacuum_vacuum_cost_limit = -1 # default vacuum cost limit for
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # autovacuum, -1 means use
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # vacuum_cost_limit
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Parameters for gathering statistics
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +default_statistics_target = 1000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# - Client connection timeouts
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +statement_timeout = 60000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +idle_in_transaction_session_timeout = 60000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# IO settings
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +effective_io_concurrency = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +track_io_timing = 'off'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Parallel worker settings
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_worker_processes = 8
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +max_parallel_workers_per_gather = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Deadlock handling and logging
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +deadlock_timeout = '5s'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +log_lock_waits = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# - Locale and Formatting -
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +datestyle = 'iso, mdy'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# These settings are initialized by initdb, but they can be changed.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +lc_messages = 'C'     # locale for system error message
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +          # strings
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +lc_monetary = 'C'     # locale for monetary formatting
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +lc_numeric = 'C'      # locale for number formatting
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +lc_time = 'C'       # locale for time formatting
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# default configuration for text search
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +default_text_search_config = 'pg_catalog.english'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/opt/gitlab/postgresql/data/pg_hba.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/opt/gitlab/postgresql/data/pg_hba.conf from fff10d to 8a626c
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/opt/gitlab/postgresql/data/pg_hba.conf	2020-01-03 12:37:13.755929725 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/opt/gitlab/postgresql/data/.chef-pg_hba20200103-12696-16wkmwt.conf	2020-01-03 12:37:14.651929842 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1,94 +1,75 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# This file is managed by gitlab-ctl. Manual changes will be
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# and run `sudo gitlab-ctl reconfigure`.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # PostgreSQL Client Authentication Configuration File
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # ===================================================
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# Refer to the "Client Authentication" section in the PostgreSQL
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# documentation for a complete description of this file.  A short
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# synopsis follows.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Refer to the "Client Authentication" section in the
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# PostgreSQL documentation for a complete description
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# of this file.  A short synopsis follows.
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # This file controls: which hosts are allowed to connect, how clients
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # are authenticated, which PostgreSQL user names they can use, which
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # databases they can access.  Records take one of these forms:
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# local      DATABASE  USER  METHOD  [OPTIONS]
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# host       DATABASE  USER  ADDRESS  METHOD  [OPTIONS]
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# hostssl    DATABASE  USER  ADDRESS  METHOD  [OPTIONS]
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# hostnossl  DATABASE  USER  ADDRESS  METHOD  [OPTIONS]
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# local      DATABASE  USER  METHOD  [OPTION]
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# host       DATABASE  USER  CIDR-ADDRESS  METHOD  [OPTION]
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# hostssl    DATABASE  USER  CIDR-ADDRESS  METHOD  [OPTION]
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# hostnossl  DATABASE  USER  CIDR-ADDRESS  METHOD  [OPTION]
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # (The uppercase items must be replaced by actual values.)
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# The first field is the connection type: "local" is a Unix-domain
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# socket, "host" is either a plain or SSL-encrypted TCP/IP socket,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# "hostssl" is an SSL-encrypted TCP/IP socket, and "hostnossl" is a
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# plain TCP/IP socket.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# The first field is the connection type: "local" is a Unix-domain socket,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# "host" is either a plain or SSL-encrypted TCP/IP socket, "hostssl" is an
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# SSL-encrypted TCP/IP socket, and "hostnossl" is a plain TCP/IP socket.
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# DATABASE can be "all", "sameuser", "samerole", "replication", a
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# database name, or a comma-separated list thereof. The "all"
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# keyword does not match "replication". Access to replication
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# must be enabled in a separate record (see example below).
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# DATABASE can be "all", "sameuser", "samerole", a database name, or
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# a comma-separated list thereof.
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# USER can be "all", a user name, a group name prefixed with "+", or a
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# comma-separated list thereof.  In both the DATABASE and USER fields
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# you can also write a file name prefixed with "@" to include names
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# from a separate file.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# USER can be "all", a user name, a group name prefixed with "+", or
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# a comma-separated list thereof.  In both the DATABASE and USER fields
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# you can also write a file name prefixed with "@" to include names from
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# a separate file.
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# ADDRESS specifies the set of hosts the record matches.  It can be a
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# host name, or it is made up of an IP address and a CIDR mask that is
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# an integer (between 0 and 32 (IPv4) or 128 (IPv6) inclusive) that
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# specifies the number of significant bits in the mask.  A host name
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# that starts with a dot (.) matches a suffix of the actual host name.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# Alternatively, you can write an IP address and netmask in separate
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# columns to specify the set of hosts.  Instead of a CIDR-address, you
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# can write "samehost" to match any of the server's own IP addresses,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# or "samenet" to match any address in any subnet that the server is
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# directly connected to.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# CIDR-ADDRESS specifies the set of hosts the record matches.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# It is made up of an IP address and a CIDR mask that is an integer
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# (between 0 and 32 (IPv4) or 128 (IPv6) inclusive) that specifies
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# the number of significant bits in the mask.  Alternatively, you can write
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# an IP address and netmask in separate columns to specify the set of hosts.
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# METHOD can be "trust", "reject", "md5", "password", "scram-sha-256",
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# "gss", "sspi", "ident", "peer", "pam", "ldap", "radius" or "cert".
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# Note that "password" sends passwords in clear text; "md5" or
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# "scram-sha-256" are preferred since they send encrypted passwords.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# METHOD can be "trust", "reject", "md5", "crypt", "password", "gss", "sspi",
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# "krb5", "ident", "pam" or "ldap".  Note that "password" sends passwords
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# in clear text; "md5" is preferred since it sends encrypted passwords.
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# OPTIONS are a set of options for the authentication in the format
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# NAME=VALUE.  The available options depend on the different
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# authentication methods -- refer to the "Client Authentication"
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# section in the documentation for a list of which options are
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# available for which authentication methods.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# OPTION is the ident map or the name of the PAM service, depending on METHOD.
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# Database and user names containing spaces, commas, quotes and other
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# special characters must be quoted.  Quoting one of the keywords
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# "all", "sameuser", "samerole" or "replication" makes the name lose
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# its special character, and just match a database or username with
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# that name.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Database and user names containing spaces, commas, quotes and other special
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# characters must be quoted. Quoting one of the keywords "all", "sameuser" or
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# "samerole" makes the name lose its special character, and just match a
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# database or username with that name.
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# This file is read on server startup and when the server receives a
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# SIGHUP signal.  If you edit the file on a running system, you have to
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# SIGHUP the server for the changes to take effect, run "pg_ctl reload",
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# or execute "SELECT pg_reload_conf()".
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -#
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# This file is read on server startup and when the postmaster receives
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# a SIGHUP signal.  If you edit the file on a running system, you have
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# to SIGHUP the postmaster for the changes to take effect.  You can use
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# "pg_ctl reload" to do that.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # Put your actual configuration here
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # ----------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):        #
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # If you want to allow non-local connections, you need to add more
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# "host" records.  In that case you will also need to make PostgreSQL
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# listen on a non-local interface via the listen_addresses
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# configuration parameter, or via the -i or -h command line switches.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# "host" records. In that case you will also need to make PostgreSQL listen
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# on a non-local interface via the listen_addresses configuration parameter,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# or via the -i or -h command line switches.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# CAUTION: Configuring the system for local "trust" authentication
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# allows any local user to connect as any PostgreSQL user, including
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# the database superuser.  If you do not trust all your local users,
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# use another authentication method.
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# TYPE  DATABASE    USER        CIDR-ADDRESS          METHOD
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# repmgr
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# TYPE  DATABASE        USER            ADDRESS                 METHOD
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # "local" is for Unix domain socket connections only
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -local   all             all                                     trust
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# IPv4 local connections:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -host    all             all             127.0.0.1/32            trust
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# IPv6 local connections:
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -host    all             all             ::1/128                 trust
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# Allow replication connections from localhost, by a user with the
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -# replication privilege.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -local   replication     all                                     trust
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -host    replication     all             127.0.0.1/32            trust
module.gitlab.aws_instance.gitlab[0] (remote-exec):       -host    replication     all             ::1/128                 trust
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +local   all         all                               peer map=gitlab
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '0600' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/opt/gitlab/postgresql/data/pg_ident.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/opt/gitlab/postgresql/data/pg_ident.conf from 297f46 to 5399a1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/opt/gitlab/postgresql/data/pg_ident.conf	2020-01-03 12:37:13.755929725 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/opt/gitlab/postgresql/data/.chef-pg_ident20200103-12696-1uq0ogq.conf	2020-01-03 12:37:14.659929843 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -40,4 +40,8 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # ----------------------------------
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):        # MAPNAME       SYSTEM-USERNAME         PG-USERNAME
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +gitlab  git  gitlab
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +gitlab  mattermost  gitlab_mattermost
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Default to a 1-1 mapping between system usernames and Postgres usernames
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +gitlab  /^(.*)$  \1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '0600' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[postgresql] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: postgresql::enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[postgresql] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgresql] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgresql
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/postgresql/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/postgresql/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/postgresql/run from none to dc5689
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/postgresql/run	2020-01-03 12:37:14.671929844 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/postgresql/.chef-run20200103-12696-1kuf68y	2020-01-03 12:37:14.671929844 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,5 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -P -U gitlab-psql:gitlab-psql -u gitlab-psql:gitlab-psql /opt/gitlab/embedded/bin/postgres -D /var/opt/gitlab/postgresql/data
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgresql/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgresql/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgresql/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgresql/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/postgresql/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/postgresql/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/postgresql/log/run from none to ce742a
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/postgresql/log/run	2020-01-03 12:37:14.675929844 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/postgresql/log/.chef-run20200103-12696-1vody5l	2020-01-03 12:37:14.675929844 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/postgresql
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/postgresql/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/postgresql/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/postgresql/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/postgresql/config	2020-01-03 12:37:14.679929845 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/postgresql/.chef-config20200103-12696-wrrx2c	2020-01-03 12:37:14.679929845 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_postgresql] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_postgresql
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_postgresql] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgresql/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgresql/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for postgresql service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/postgresql/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/postgresql/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgresql/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgresql/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/postgresql/control/t] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/postgresql/control/t
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/postgresql/control/t from none to 05ae12
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/postgresql/control/t	2020-01-03 12:37:14.687929846 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/postgresql/control/.chef-t20200103-12696-tbwrd2	2020-01-03 12:37:14.687929846 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,4 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +echo "received TERM from runit, sending INT instead to force quit connections"
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/opt/gitlab/embedded/bin/sv interrupt postgresql
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/postgresql] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/postgresql to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/postgresql/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/postgresql/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_postgresql] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for postgresql service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/control/t] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/postgresql] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/postgresql] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/postgresql to /opt/gitlab/sv/postgresql
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for postgresql service socket] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for postgresql service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service/postgresql/supervise] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change mode from '0700' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service/postgresql/log/supervise] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change mode from '0700' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/supervise/ok] action touch
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create new file /opt/gitlab/sv/postgresql/supervise/ok
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change owner from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change group from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - update utime on file /opt/gitlab/sv/postgresql/supervise/ok
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/log/supervise/ok] action touch
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create new file /opt/gitlab/sv/postgresql/log/supervise/ok
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change owner from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change group from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - update utime on file /opt/gitlab/sv/postgresql/log/supervise/ok
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/supervise/status] action touch
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change owner from 'root' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change group from 'root' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - update utime on file /opt/gitlab/sv/postgresql/supervise/status
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/log/supervise/status] action touch
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change owner from 'root' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change group from 'root' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - update utime on file /opt/gitlab/sv/postgresql/log/supervise/status
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/supervise/control] action touch
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create new file /opt/gitlab/sv/postgresql/supervise/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change owner from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change group from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - update utime on file /opt/gitlab/sv/postgresql/supervise/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/log/supervise/control] action touch
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create new file /opt/gitlab/sv/postgresql/log/supervise/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change owner from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change group from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - update utime on file /opt/gitlab/sv/postgresql/log/supervise/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/postgresql/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_postgresql] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for postgresql service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgresql/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgresql/control/t] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/postgresql] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/postgresql] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for postgresql service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service/postgresql/supervise] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service/postgresql/log/supervise] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/supervise/ok] action touch (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/log/supervise/ok] action touch (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/supervise/status] action touch (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/log/supervise/status] action touch
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change owner from 'root' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - change group from 'root' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - update utime on file /opt/gitlab/sv/postgresql/log/supervise/status
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/supervise/control] action touch (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgresql/log/supervise/control] action touch (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/postgresql] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for postgresql service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service/postgresql/supervise] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service/postgresql/log/supervise] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/postgresql/supervise/ok] action touch (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/postgresql/log/supervise/ok] action touch (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/postgresql/supervise/status] action touch (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/postgresql/log/supervise/status] action touch
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from 'root' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from 'root' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update utime on file /opt/gitlab/sv/postgresql/log/supervise/status
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/postgresql/supervise/control] action touch (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/postgresql/log/supervise/control] action touch (skipped due to only_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start postgresql] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: postgresql: (pid 13380) 4s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start postgresql
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/opt/gitlab/etc/gitlab-psql-rc] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /opt/gitlab/etc/gitlab-psql-rc
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /opt/gitlab/etc/gitlab-psql-rc from none to b7b8fc
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /opt/gitlab/etc/gitlab-psql-rc	2020-01-03 12:37:20.827930485 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /opt/gitlab/etc/.chef-gitlab-psql-rc20200103-12696-1xq0586	2020-01-03 12:37:20.827930485 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,6 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +psql_user='gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +psql_group='gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +psql_host='/var/opt/gitlab/postgresql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +psql_port='5432'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +psql_dbname='gitlabhq_production'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * postgresql_user[gitlab] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[create gitlab postgresql user] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] CREATE ROLE
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute /opt/gitlab/bin/gitlab-psql -d template1 -c "CREATE USER \"gitlab\""
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[create gitlabhq_production database] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/embedded/bin/createdb --port 5432 -h /var/opt/gitlab/postgresql -O gitlab gitlabhq_production
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * postgresql_user[gitlab_replicator] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[create gitlab_replicator postgresql user] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] CREATE ROLE
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute /opt/gitlab/bin/gitlab-psql -d template1 -c "CREATE USER \"gitlab_replicator\""
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[set options for gitlab_replicator postgresql user] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] ALTER ROLE
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute /opt/gitlab/bin/gitlab-psql -d template1 -c "ALTER USER \"gitlab_replicator\" replication"
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * postgresql_extension[pg_trgm] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * postgresql_query[enable pg_trgm extension] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * execute[enable pg_trgm extension (postgresql)] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):         [execute] CREATE EXTENSION
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute /opt/gitlab/bin/gitlab-psql -d gitlabhq_production -c "CREATE EXTENSION IF NOT EXISTS pg_trgm"
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * ruby_block[warn pending postgresql restart] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[reload postgresql] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[start postgresql] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::database_migrations
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * bash[migrate gitlab-rails database] action run
module.gitlab.aws_instance.gitlab[0]: Still creating... [2m40s elapsed]
module.gitlab.aws_instance.gitlab[0]: Still creating... [2m50s elapsed]

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] -- enable_extension("pg_trgm")
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0102s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- enable_extension("plpgsql")
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("abuse_reports", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0275s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("alerts_service_data", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("allowed_email_domains", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0073s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("analytics_cycle_analytics_group_stages", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0264s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("analytics_cycle_analytics_project_stages", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0228s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("analytics_language_trend_repository_languages", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0100s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("analytics_repository_file_commits", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0115s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("analytics_repository_file_edits", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0111s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("analytics_repository_files", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0091s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("appearances", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0064s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("application_setting_terms", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0060s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("application_settings", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0751s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approval_merge_request_rule_sources", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0111s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approval_merge_request_rules", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0261s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approval_merge_request_rules_approved_approvers", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0110s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approval_merge_request_rules_groups", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0108s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approval_merge_request_rules_users", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0107s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approval_project_rules", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0171s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approval_project_rules_groups", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0110s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approval_project_rules_users", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0114s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approvals", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0110s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approver_groups", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0133s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("approvers", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0128s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("audit_events", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("award_emoji", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0130s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("aws_roles", {:primary_key=>"user_id", :id=>:integer, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0132s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("badges", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0131s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("board_assignees", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0110s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("board_group_recent_visits", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0185s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("board_labels", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0109s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("board_project_recent_visits", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0183s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("boards", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0177s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("broadcast_messages", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0103s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("chat_names", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0132s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("chat_teams", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_build_needs", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0100s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_build_trace_chunks", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0094s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_build_trace_section_names", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0095s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_build_trace_sections", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0119s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_builds", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.1002s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_builds_metadata", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0215s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_builds_runner_session", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0097s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_group_variables", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0106s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_job_artifacts", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0248s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_job_variables", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0140s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_pipeline_chat_data", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_pipeline_schedule_variables", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0113s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_pipeline_schedules", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0181s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_pipeline_variables", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0141s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_pipelines", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0585s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_runner_namespaces", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0114s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_runner_projects", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0112s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_runners", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0300s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_sources_pipelines", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0226s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_stages", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0206s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_subscriptions_projects", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0111s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_trigger_requests", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_triggers", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ci_variables", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0145s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("cluster_groups", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0107s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("cluster_platforms_kubernetes", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0099s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("cluster_projects", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0111s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("cluster_providers_aws", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0189s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("cluster_providers_gcp", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0144s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0184s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_applications_cert_managers", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0100s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_applications_crossplane", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0096s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_applications_elastic_stacks", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0101s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_applications_helm", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0100s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_applications_ingress", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0095s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_applications_jupyter", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0133s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_applications_knative", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_applications_prometheus", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_applications_runners", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0139s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("clusters_kubernetes_namespaces", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0280s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("commit_user_mentions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0138s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("container_expiration_policies", {:primary_key=>"project_id", :id=>:bigint, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0076s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("container_repositories", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0137s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("conversational_development_index_metrics", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0064s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("dependency_proxy_blobs", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0101s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("dependency_proxy_group_settings", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0077s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("deploy_keys_projects", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0111s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("deploy_tokens", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0185s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("deployment_merge_requests", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0081s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("deployments", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0577s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("description_versions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0169s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("design_management_designs", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0132s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("design_management_designs_versions", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0158s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("design_management_versions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0167s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("design_user_mentions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0139s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("draft_notes", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0169s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("elasticsearch_indexed_namespaces", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0049s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("elasticsearch_indexed_projects", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0050s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("emails", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0176s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("environments", {:id=>:serial, :force=>:cascade})

module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0240s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("epic_issues", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0120s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("epic_metrics", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0074s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("epic_user_mentions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0170s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("epics", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0462s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("events", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0312s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("evidences", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0100s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("external_pull_requests", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0097s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("feature_gates", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0100s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("features", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0094s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("fork_network_members", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0141s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("fork_networks", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0095s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("forked_project_links", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0074s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_cache_invalidation_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0058s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_container_repository_updated_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0075s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_event_log", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0511s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_hashed_storage_attachments_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0101s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_hashed_storage_migrated_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0100s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_job_artifact_deleted_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0099s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_lfs_object_deleted_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0095s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_node_namespace_links", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0154s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_node_statuses", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0107s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_nodes", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0194s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_repositories_changed_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0078s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_repository_created_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0103s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_repository_deleted_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0104s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_repository_renamed_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0105s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_repository_updated_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0141s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_reset_checksum_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0076s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("geo_upload_deleted_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("gitlab_subscription_histories", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0078s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("gitlab_subscriptions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0116s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("gpg_key_subkeys", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0173s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("gpg_keys", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0170s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("gpg_signatures", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0253s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("grafana_integrations", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0139s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("group_custom_attributes", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0137s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("group_deletion_schedules", {:primary_key=>"group_id", :id=>:bigint, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0107s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("group_group_links", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0126s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("historical_data", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0040s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("identities", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0166s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("import_export_uploads", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0174s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("import_failures", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0133s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("index_statuses", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0106s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("insights", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0108s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("internal_ids", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0187s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ip_restrictions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0092s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("issue_assignees", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0083s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("issue_links", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0156s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("issue_metrics", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0121s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("issue_tracker_data", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0101s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("issue_user_mentions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0196s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("issues", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0911s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("issues_prometheus_alert_events", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0085s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("issues_self_managed_prometheus_alert_events", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0085s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("jira_connect_installations", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("jira_connect_subscriptions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0148s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("jira_tracker_data", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("keys", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0247s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("label_links", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0135s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("label_priorities", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0153s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("labels", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0326s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("ldap_group_links", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0062s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("lfs_file_locks", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("lfs_objects", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0142s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("lfs_objects_projects", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0113s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("licenses", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0061s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("list_user_preferences", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0157s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("lists", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0242s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("members", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0341s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_request_assignees", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0153s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_request_blocks", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0117s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_request_diff_commits", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0167s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_request_diff_files", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0076s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_request_diffs", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0137s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_request_metrics", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0337s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_request_user_mentions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0173s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_requests", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.1056s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_requests_closing_issues", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0110s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("merge_trains", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0214s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("milestone_releases", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0091s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("milestones", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0248s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("namespace_aggregation_schedules", {:primary_key=>"namespace_id", :id=>:integer, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0074s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("namespace_root_storage_statistics", {:primary_key=>"namespace_id", :id=>:integer, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0086s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("namespace_statistics", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0085s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("namespaces", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0715s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("note_diff_files", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("notes", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0424s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("notification_settings", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0176s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("oauth_access_grants", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0106s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("oauth_access_tokens", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0199s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("oauth_applications", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0138s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("oauth_openid_requests", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0099s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("operations_feature_flag_scopes", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0104s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("operations_feature_flags", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("operations_feature_flags_clients", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0093s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("packages_build_infos", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0110s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("packages_conan_file_metadata", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("packages_conan_metadata", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0095s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("packages_dependencies", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0093s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("packages_dependency_links", {:force=>:cascade})

module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0134s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("packages_maven_metadata", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0096s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("packages_package_files", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0101s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("packages_package_tags", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0071s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("packages_packages", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0153s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("pages_domain_acme_orders", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0138s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("pages_domains", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0405s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("path_locks", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0183s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("personal_access_tokens", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0185s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("plan_limits", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0080s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("plans", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0097s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("pool_repositories", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0172s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("programming_languages", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_alerting_settings", {:primary_key=>"project_id", :id=>:integer, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0056s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_aliases", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0133s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_authorizations", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0083s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_auto_devops", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0073s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_ci_cd_settings", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0113s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_custom_attributes", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0131s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_daily_statistics", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0080s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_deploy_tokens", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0111s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_error_tracking_settings", {:primary_key=>"project_id", :id=>:integer, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0060s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_feature_usages", {:primary_key=>"project_id", :id=>:integer, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0142s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_features", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0076s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_group_links", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0114s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_import_data", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0097s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_incident_management_settings", {:primary_key=>"project_id", :id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0065s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_metrics_settings", {:primary_key=>"project_id", :id=>:integer, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0057s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_mirror_data", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0292s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_pages_metadata", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0088s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_repositories", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0177s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_repository_states", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0301s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_statistics", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0127s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("project_tracing_settings", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0102s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("projects", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.1088s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("prometheus_alert_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0134s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("prometheus_alerts", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0161s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("prometheus_metrics", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0211s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("protected_branch_merge_access_levels", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0152s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("protected_branch_push_access_levels", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0154s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("protected_branch_unprotect_access_levels", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0153s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("protected_branches", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0151s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("protected_environment_deploy_access_levels", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0155s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("protected_environments", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("protected_tag_create_access_levels", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0155s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("protected_tags", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0143s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("push_event_payloads", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0076s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("push_rules", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0157s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("redirect_routes", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0186s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("release_links", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("releases", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("remote_mirrors", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0154s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("repository_languages", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0060s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("resource_label_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0259s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("reviews", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0141s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("routes", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0176s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("saml_providers", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0168s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("scim_oauth_access_tokens", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0096s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("self_managed_prometheus_alert_events", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0138s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("sent_notifications", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("sentry_issues", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0077s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("serverless_domain_cluster", {:primary_key=>"uuid", :id=>:string, :limit=>14, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0147s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("service_desk_settings", {:primary_key=>"project_id", :id=>:bigint, :default=>nil, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0058s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("services", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0204s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("shards", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0094s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("slack_integrations", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0163s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("smartcard_identities", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0168s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("snippet_user_mentions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.1124s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("snippets", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0310s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("software_license_policies", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0122s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("software_licenses", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0131s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("spam_logs", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0067s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("subscriptions", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0134s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("suggestions", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0108s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("system_note_metadata", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0132s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("taggings", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0202s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("tags", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0120s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("term_agreements", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0143s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("timelogs", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0187s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("todos", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0384s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("trending_projects", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0079s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("u2f_registrations", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0136s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("uploads", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0214s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("user_agent_details", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0104s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("user_callouts", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0116s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("user_custom_attributes", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0140s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("user_interacted_projects", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0086s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("user_preferences", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0113s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("user_statuses", {:primary_key=>"user_id", :id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0101s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("user_synced_attributes_metadata", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0102s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("users", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.1004s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("users_ops_dashboard_projects", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0112s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("users_security_dashboard_projects", {:id=>false, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0084s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("users_star_projects", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0126s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("vulnerabilities", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0454s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("vulnerability_feedback", {:id=>:serial, :force=>:cascade})

module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0295s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("vulnerability_identifiers", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0098s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("vulnerability_issue_links", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0150s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("vulnerability_occurrence_identifiers", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0121s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("vulnerability_occurrence_pipelines", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0112s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("vulnerability_occurrences", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0291s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("vulnerability_scanners", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0097s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("web_hook_logs", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0145s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("web_hooks", {:id=>:serial, :force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0163s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- create_table("zoom_meetings", {:force=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0189s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("alerts_service_data", "services", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0022s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("allowed_email_domains", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0021s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_cycle_analytics_group_stages", "labels", {:column=>"end_event_label_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_cycle_analytics_group_stages", "labels", {:column=>"start_event_label_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_cycle_analytics_group_stages", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_cycle_analytics_project_stages", "labels", {:column=>"end_event_label_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_cycle_analytics_project_stages", "labels", {:column=>"start_event_label_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_cycle_analytics_project_stages", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0024s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_language_trend_repository_languages", "programming_languages", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_language_trend_repository_languages", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_repository_file_commits", "analytics_repository_files", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_repository_file_commits", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_repository_file_edits", "analytics_repository_files", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_repository_file_edits", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("analytics_repository_files", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("application_settings", "namespaces", {:column=>"custom_project_templates_group_id", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0025s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("application_settings", "projects", {:column=>"file_template_project_id", :name=>"fk_ec757bd087", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("application_settings", "projects", {:column=>"instance_administration_project_id", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("application_settings", "users", {:column=>"usage_stats_set_by_user_id", :name=>"fk_964370041d", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0026s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_merge_request_rule_sources", "approval_merge_request_rules", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_merge_request_rule_sources", "approval_project_rules", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_merge_request_rules", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0023s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_merge_request_rules_approved_approvers", "approval_merge_request_rules", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_merge_request_rules_approved_approvers", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_merge_request_rules_groups", "approval_merge_request_rules", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_merge_request_rules_groups", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_merge_request_rules_users", "approval_merge_request_rules", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_merge_request_rules_users", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_project_rules", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_project_rules_groups", "approval_project_rules", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_project_rules_groups", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_project_rules_users", "approval_project_rules", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approval_project_rules_users", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approvals", "merge_requests", {:name=>"fk_310d714958", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("approver_groups", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("aws_roles", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("badges", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("badges", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_assignees", "boards", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_assignees", "users", {:column=>"assignee_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_group_recent_visits", "boards", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_group_recent_visits", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_group_recent_visits", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_labels", "boards", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_labels", "labels", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_project_recent_visits", "boards", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_project_recent_visits", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("board_project_recent_visits", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("boards", "namespaces", {:column=>"group_id", :name=>"fk_1e9a074a35", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("boards", "projects", {:name=>"fk_f15266b5f9", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("chat_teams", "namespaces", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_build_needs", "ci_builds", {:column=>"build_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0024s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_build_trace_chunks", "ci_builds", {:column=>"build_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_build_trace_section_names", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_build_trace_sections", "ci_build_trace_section_names", {:column=>"section_name_id", :name=>"fk_264e112c66", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_build_trace_sections", "ci_builds", {:column=>"build_id", :name=>"fk_4ebe41f502", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_build_trace_sections", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_builds", "ci_pipelines", {:column=>"auto_canceled_by_id", :name=>"fk_a2141b1522", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_builds", "ci_pipelines", {:column=>"commit_id", :name=>"fk_d3130c9a7f", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_builds", "ci_pipelines", {:column=>"upstream_pipeline_id", :name=>"fk_87f4cefcda", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_builds", "ci_stages", {:column=>"stage_id", :name=>"fk_3a9eaa254d", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_builds", "projects", {:name=>"fk_befce0568a", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_builds_metadata", "ci_builds", {:column=>"build_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_builds_metadata", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_builds_runner_session", "ci_builds", {:column=>"build_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0037s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_group_variables", "namespaces", {:column=>"group_id", :name=>"fk_33ae4d58d8", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_job_artifacts", "ci_builds", {:column=>"job_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_job_artifacts", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_job_variables", "ci_builds", {:column=>"job_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipeline_chat_data", "chat_names", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipeline_chat_data", "ci_pipelines", {:column=>"pipeline_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipeline_schedule_variables", "ci_pipeline_schedules", {:column=>"pipeline_schedule_id", :name=>"fk_41c35fda51", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipeline_schedules", "projects", {:name=>"fk_8ead60fcc4", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipeline_schedules", "users", {:column=>"owner_id", :name=>"fk_9ea99f58d2", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipeline_variables", "ci_pipelines", {:column=>"pipeline_id", :name=>"fk_f29c5f4380", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipelines", "ci_pipeline_schedules", {:column=>"pipeline_schedule_id", :name=>"fk_3d34ab2e06", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipelines", "ci_pipelines", {:column=>"auto_canceled_by_id", :name=>"fk_262d4c2d19", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipelines", "external_pull_requests", {:name=>"fk_190998ef09", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipelines", "merge_requests", {:name=>"fk_a23be95014", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_pipelines", "projects", {:name=>"fk_86635dbd80", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_runner_namespaces", "ci_runners", {:column=>"runner_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_runner_namespaces", "namespaces", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_runner_projects", "projects", {:name=>"fk_4478a6f1e4", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_sources_pipelines", "ci_builds", {:column=>"source_job_id", :name=>"fk_be5624bf37", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_sources_pipelines", "ci_pipelines", {:column=>"pipeline_id", :name=>"fk_e1bad85861", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_sources_pipelines", "ci_pipelines", {:column=>"source_pipeline_id", :name=>"fk_d4e29af7d7", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_sources_pipelines", "projects", {:column=>"source_project_id", :name=>"fk_acd9737679", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_sources_pipelines", "projects", {:name=>"fk_1e53c97c0a", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_stages", "ci_pipelines", {:column=>"pipeline_id", :name=>"fk_fb57e6cc56", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_stages", "projects", {:name=>"fk_2360681d1d", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_subscriptions_projects", "projects", {:column=>"downstream_project_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_subscriptions_projects", "projects", {:column=>"upstream_project_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_trigger_requests", "ci_triggers", {:column=>"trigger_id", :name=>"fk_b8ec8b7245", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_triggers", "projects", {:name=>"fk_e3e63f966e", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_triggers", "users", {:column=>"owner_id", :name=>"fk_e8e10d1964", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ci_variables", "projects", {:name=>"fk_ada5eb64b3", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("cluster_groups", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("cluster_groups", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("cluster_platforms_kubernetes", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("cluster_projects", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("cluster_projects", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("cluster_providers_aws", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("cluster_providers_aws", "users", {:column=>"created_by_user_id", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("cluster_providers_gcp", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters", "projects", {:column=>"management_project_id", :name=>"fk_f05c5e5a42", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters", "users", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_cert_managers", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_crossplane", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_elastic_stacks", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_helm", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_ingress", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_jupyter", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_jupyter", "oauth_applications", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_knative", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0024s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_prometheus", "clusters", {:name=>"fk_557e773639", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_runners", "ci_runners", {:column=>"runner_id", :name=>"fk_02de2ded36", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_applications_runners", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_kubernetes_namespaces", "cluster_projects", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_kubernetes_namespaces", "clusters", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_kubernetes_namespaces", "environments", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("clusters_kubernetes_namespaces", "projects", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("commit_user_mentions", "notes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("container_expiration_policies", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("container_repositories", "projects")
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("dependency_proxy_blobs", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("dependency_proxy_group_settings", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("deploy_keys_projects", "projects", {:name=>"fk_58a901ca7e", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("deployment_merge_requests", "deployments", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("deployment_merge_requests", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("deployments", "clusters", {:name=>"fk_289bba3222", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("deployments", "projects", {:name=>"fk_b9a3851b82", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("description_versions", "epics", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0022s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("description_versions", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0021s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("description_versions", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("design_management_designs", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("design_management_designs", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("design_management_designs_versions", "design_management_designs", {:column=>"design_id", :name=>"fk_03c671965c", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0030s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("design_management_designs_versions", "design_management_versions", {:column=>"version_id", :name=>"fk_f4d25ba00c", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("design_management_versions", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("design_management_versions", "users", {:column=>"author_id", :name=>"fk_c1440b4896", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("design_user_mentions", "design_management_designs", {:column=>"design_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("design_user_mentions", "notes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("draft_notes", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("draft_notes", "users", {:column=>"author_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("elasticsearch_indexed_namespaces", "namespaces", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("elasticsearch_indexed_projects", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("environments", "projects", {:name=>"fk_d1c8c1da6a", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epic_issues", "epics", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epic_issues", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epic_metrics", "epics", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epic_user_mentions", "epics", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epic_user_mentions", "notes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epics", "epics", {:column=>"due_date_sourcing_epic_id", :name=>"fk_013c9f36ca", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epics", "epics", {:column=>"parent_id", :name=>"fk_25b99c1be3", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epics", "epics", {:column=>"start_date_sourcing_epic_id", :name=>"fk_9d480c64b2", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epics", "milestones", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epics", "namespaces", {:column=>"group_id", :name=>"fk_f081aa4489", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epics", "users", {:column=>"assignee_id", :name=>"fk_dccd3f98fc", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epics", "users", {:column=>"author_id", :name=>"fk_3654b61b03", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("epics", "users", {:column=>"closed_by_id", :name=>"fk_aa5798e761", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("events", "namespaces", {:column=>"group_id", :name=>"fk_61fbf6ca48", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("events", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0027s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("events", "users", {:column=>"author_id", :name=>"fk_edfd187b6f", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("evidences", "releases", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("external_pull_requests", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("fork_network_members", "fork_networks", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("fork_network_members", "projects", {:column=>"forked_from_project_id", :name=>"fk_b01280dae4", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("fork_network_members", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("fork_networks", "projects", {:column=>"root_project_id", :name=>"fk_e7b436b2b5", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("forked_project_links", "projects", {:column=>"forked_to_project_id", :name=>"fk_434510edb0", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_container_repository_updated_events", "container_repositories", {:name=>"fk_212c89c706", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_cache_invalidation_events", {:column=>"cache_invalidation_event_id", :name=>"fk_42c3b54bed", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_container_repository_updated_events", {:column=>"container_repository_updated_event_id", :name=>"fk_6ada82d42a", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_hashed_storage_migrated_events", {:column=>"hashed_storage_migrated_event_id", :name=>"fk_27548c6db3", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_job_artifact_deleted_events", {:column=>"job_artifact_deleted_event_id", :name=>"fk_176d3fbb5d", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_lfs_object_deleted_events", {:column=>"lfs_object_deleted_event_id", :name=>"fk_d5af95fcd9", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_repositories_changed_events", {:column=>"repositories_changed_event_id", :name=>"fk_4a99ebfd60", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_repository_created_events", {:column=>"repository_created_event_id", :name=>"fk_9b9afb1916", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_repository_deleted_events", {:column=>"repository_deleted_event_id", :name=>"fk_c4b1c1f66e", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_repository_renamed_events", {:column=>"repository_renamed_event_id", :name=>"fk_86c84214ec", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_repository_updated_events", {:column=>"repository_updated_event_id", :name=>"fk_78a6492f68", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_reset_checksum_events", {:column=>"reset_checksum_event_id", :name=>"fk_cff7185ad2", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_event_log", "geo_upload_deleted_events", {:column=>"upload_deleted_event_id", :name=>"fk_c1f241c70d", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_hashed_storage_attachments_events", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_hashed_storage_migrated_events", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_node_namespace_links", "geo_nodes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_node_namespace_links", "namespaces", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_node_statuses", "geo_nodes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_repositories_changed_events", "geo_nodes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_repository_created_events", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_repository_renamed_events", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_repository_updated_events", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("geo_reset_checksum_events", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("gitlab_subscriptions", "namespaces", {:name=>"fk_e2595d00a1", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("gitlab_subscriptions", "plans", {:column=>"hosted_plan_id", :name=>"fk_bd0c4019c3", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("gpg_key_subkeys", "gpg_keys", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("gpg_keys", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("gpg_signatures", "gpg_key_subkeys", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("gpg_signatures", "gpg_keys", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("gpg_signatures", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0027s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("grafana_integrations", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("group_custom_attributes", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("group_deletion_schedules", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("group_deletion_schedules", "users", {:name=>"fk_11e3ebfcdd", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("group_group_links", "namespaces", {:column=>"shared_group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("group_group_links", "namespaces", {:column=>"shared_with_group_id", :on_delete=>:cascade})

module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0031s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("identities", "saml_providers", {:name=>"fk_aade90f0fc", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("import_export_uploads", "namespaces", {:column=>"group_id", :name=>"fk_83319d9721", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("import_export_uploads", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("index_statuses", "projects", {:name=>"fk_74b2492545", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("insights", "namespaces", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("insights", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("internal_ids", "namespaces", {:name=>"fk_162941d509", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("internal_ids", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("ip_restrictions", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issue_assignees", "issues", {:name=>"fk_b7d881734a", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issue_assignees", "users", {:name=>"fk_5e0c8d9154", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issue_links", "issues", {:column=>"source_id", :name=>"fk_c900194ff2", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issue_links", "issues", {:column=>"target_id", :name=>"fk_e71bb44f1f", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0030s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issue_metrics", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issue_tracker_data", "services", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issue_user_mentions", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issue_user_mentions", "notes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues", "epics", {:column=>"promoted_to_epic_id", :name=>"fk_df75a7c8b8", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues", "issues", {:column=>"duplicated_to_id", :name=>"fk_9c4516d665", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues", "issues", {:column=>"moved_to_id", :name=>"fk_a194299be1", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues", "milestones", {:name=>"fk_96b1dd429c", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues", "projects", {:name=>"fk_899c8f3231", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues", "users", {:column=>"author_id", :name=>"fk_05f1e72feb", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues", "users", {:column=>"closed_by_id", :name=>"fk_c63cbf6c25", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues", "users", {:column=>"updated_by_id", :name=>"fk_ffed080f01", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues_prometheus_alert_events", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues_prometheus_alert_events", "prometheus_alert_events", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues_self_managed_prometheus_alert_events", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("issues_self_managed_prometheus_alert_events", "self_managed_prometheus_alert_events", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("jira_connect_subscriptions", "jira_connect_installations", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("jira_connect_subscriptions", "namespaces", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("jira_tracker_data", "services", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("label_links", "labels", {:name=>"fk_d97dd08678", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("label_priorities", "labels", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("label_priorities", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("labels", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("labels", "projects", {:name=>"fk_7de4989a69", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("lfs_file_locks", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("lfs_file_locks", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("list_user_preferences", "lists", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("list_user_preferences", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("lists", "boards", {:name=>"fk_0d3f677137", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("lists", "labels", {:name=>"fk_7a5553d60f", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("lists", "milestones", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("lists", "users", {:name=>"fk_d6cf4279f7", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("members", "users", {:name=>"fk_2e88fb7ce9", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_assignees", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_assignees", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_blocks", "merge_requests", {:column=>"blocked_merge_request_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_blocks", "merge_requests", {:column=>"blocking_merge_request_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_diff_commits", "merge_request_diffs", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_diff_files", "merge_request_diffs", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_diffs", "merge_requests", {:name=>"fk_8483f3258f", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_metrics", "ci_pipelines", {:column=>"pipeline_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_metrics", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_metrics", "users", {:column=>"latest_closed_by_id", :name=>"fk_ae440388cc", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_metrics", "users", {:column=>"merged_by_id", :name=>"fk_7f28d925f3", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_user_mentions", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_request_user_mentions", "notes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests", "ci_pipelines", {:column=>"head_pipeline_id", :name=>"fk_fd82eae0b9", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests", "merge_request_diffs", {:column=>"latest_merge_request_diff_id", :name=>"fk_06067f5644", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests", "milestones", {:name=>"fk_6a5165a692", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests", "projects", {:column=>"source_project_id", :name=>"fk_3308fe130c", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0021s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests", "projects", {:column=>"target_project_id", :name=>"fk_a6963e8447", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests", "users", {:column=>"assignee_id", :name=>"fk_6149611a04", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests", "users", {:column=>"author_id", :name=>"fk_e719a85f8a", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests", "users", {:column=>"merge_user_id", :name=>"fk_ad525e1f87", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests", "users", {:column=>"updated_by_id", :name=>"fk_641731faff", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests_closing_issues", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_requests_closing_issues", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_trains", "ci_pipelines", {:column=>"pipeline_id", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_trains", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_trains", "projects", {:column=>"target_project_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("merge_trains", "users", {:on_delete=>:cascade})

module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0035s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("milestone_releases", "milestones", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("milestone_releases", "releases", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("milestones", "namespaces", {:column=>"group_id", :name=>"fk_95650a40d4", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("milestones", "projects", {:name=>"fk_9bd0a0c791", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("namespace_aggregation_schedules", "namespaces", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("namespace_root_storage_statistics", "namespaces", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("namespace_statistics", "namespaces", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("namespaces", "namespaces", {:column=>"custom_project_templates_group_id", :name=>"fk_e7a0b20a6b", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0026s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("namespaces", "plans", {:name=>"fk_fdd12e5b80", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("namespaces", "projects", {:column=>"file_template_project_id", :name=>"fk_319256d87a", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0021s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("note_diff_files", "notes", {:column=>"diff_note_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("notes", "projects", {:name=>"fk_99e097b079", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("notes", "reviews", {:name=>"fk_2e82291620", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("notification_settings", "users", {:name=>"fk_0c95e91db7", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("oauth_openid_requests", "oauth_access_grants", {:column=>"access_grant_id", :name=>"fk_77114b3b09", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("operations_feature_flag_scopes", "operations_feature_flags", {:column=>"feature_flag_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("operations_feature_flags", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("operations_feature_flags_clients", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_build_infos", "ci_pipelines", {:column=>"pipeline_id", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_build_infos", "packages_packages", {:column=>"package_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_conan_file_metadata", "packages_package_files", {:column=>"package_file_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_conan_metadata", "packages_packages", {:column=>"package_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_dependency_links", "packages_dependencies", {:column=>"dependency_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_dependency_links", "packages_packages", {:column=>"package_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_maven_metadata", "packages_packages", {:column=>"package_id", :name=>"fk_be88aed360", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_package_files", "packages_packages", {:column=>"package_id", :name=>"fk_86f0f182f8", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_package_tags", "packages_packages", {:column=>"package_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("packages_packages", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("pages_domain_acme_orders", "pages_domains", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("pages_domains", "projects", {:name=>"fk_ea2f6dfc6f", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("path_locks", "projects", {:name=>"fk_5265c98f24", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("path_locks", "users")
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0024s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("personal_access_tokens", "users")
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("plan_limits", "plans", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("pool_repositories", "projects", {:column=>"source_project_id", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("pool_repositories", "shards", {:on_delete=>:restrict})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_alerting_settings", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_aliases", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_authorizations", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_authorizations", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_auto_devops", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_ci_cd_settings", "projects", {:name=>"fk_24c15d2f2e", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_custom_attributes", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_daily_statistics", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0022s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_deploy_tokens", "deploy_tokens", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_deploy_tokens", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_error_tracking_settings", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_feature_usages", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_features", "projects", {:name=>"fk_18513d9b92", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_group_links", "projects", {:name=>"fk_daa8cee94c", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_import_data", "projects", {:name=>"fk_ffb9ee3a10", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_incident_management_settings", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_metrics_settings", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_mirror_data", "projects", {:name=>"fk_d1aad367d7", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_pages_metadata", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_repositories", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_repositories", "shards", {:on_delete=>:restrict})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_repository_states", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_statistics", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("project_tracing_settings", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("projects", "pool_repositories", {:name=>"fk_6e5c14658a", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("projects", "users", {:column=>"marked_for_deletion_by_user_id", :name=>"fk_25d8780d11", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("prometheus_alert_events", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("prometheus_alert_events", "prometheus_alerts", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("prometheus_alerts", "environments", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("prometheus_alerts", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("prometheus_alerts", "prometheus_metrics", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("prometheus_metrics", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branch_merge_access_levels", "namespaces", {:column=>"group_id", :name=>"fk_98f3d044fe", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branch_merge_access_levels", "protected_branches", {:name=>"fk_8a3072ccb3", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branch_merge_access_levels", "users")
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branch_push_access_levels", "namespaces", {:column=>"group_id", :name=>"fk_7111b68cdb", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branch_push_access_levels", "protected_branches", {:name=>"fk_9ffc86a3d9", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branch_push_access_levels", "users")
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branch_unprotect_access_levels", "namespaces", {:column=>"group_id", :on_delete=>:cascade})

module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0035s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branch_unprotect_access_levels", "protected_branches", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branch_unprotect_access_levels", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_branches", "projects", {:name=>"fk_7a9c6d93e7", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_environment_deploy_access_levels", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_environment_deploy_access_levels", "protected_environments", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_environment_deploy_access_levels", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_environments", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_tag_create_access_levels", "namespaces", {:column=>"group_id", :name=>"fk_b4eb82fe3c", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_tag_create_access_levels", "protected_tags", {:name=>"fk_f7dfda8c51", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_tag_create_access_levels", "users")
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("protected_tags", "projects", {:name=>"fk_8e4af87648", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0021s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("push_event_payloads", "events", {:name=>"fk_36c74129da", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("push_rules", "projects", {:name=>"fk_83b29894de", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("release_links", "releases", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("releases", "projects", {:name=>"fk_47fe2a0596", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("releases", "users", {:column=>"author_id", :name=>"fk_8e4456f90f", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("remote_mirrors", "projects", {:name=>"fk_43a9aa4ca8", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("repository_languages", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("resource_label_events", "epics", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("resource_label_events", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("resource_label_events", "labels", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("resource_label_events", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("resource_label_events", "users", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("reviews", "merge_requests", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("reviews", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("reviews", "users", {:column=>"author_id", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("saml_providers", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("scim_oauth_access_tokens", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("self_managed_prometheus_alert_events", "environments", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("self_managed_prometheus_alert_events", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("sentry_issues", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("serverless_domain_cluster", "clusters_applications_knative", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("serverless_domain_cluster", "pages_domains", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("serverless_domain_cluster", "users", {:column=>"creator_id", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("service_desk_settings", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("services", "projects", {:name=>"fk_71cce407f9", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("slack_integrations", "services", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("smartcard_identities", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("snippet_user_mentions", "notes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("snippet_user_mentions", "snippets", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("snippets", "projects", {:name=>"fk_be41fd4bb7", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("software_license_policies", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("software_license_policies", "software_licenses", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("subscriptions", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("suggestions", "notes", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("system_note_metadata", "description_versions", {:name=>"fk_fbd87415c9", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("system_note_metadata", "notes", {:name=>"fk_d83a918cb1", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("term_agreements", "application_setting_terms", {:column=>"term_id"})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("term_agreements", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("timelogs", "issues", {:name=>"fk_timelogs_issues_issue_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("timelogs", "merge_requests", {:name=>"fk_timelogs_merge_requests_merge_request_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("todos", "namespaces", {:column=>"group_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("todos", "notes", {:name=>"fk_91d1f47b13", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("todos", "projects", {:name=>"fk_45054f9c45", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("todos", "users", {:column=>"author_id", :name=>"fk_ccf0373936", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("todos", "users", {:name=>"fk_d94154aa95", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("trending_projects", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("u2f_registrations", "users")
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("user_callouts", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("user_custom_attributes", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("user_interacted_projects", "projects", {:name=>"fk_722ceba4f7", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("user_interacted_projects", "users", {:name=>"fk_0894651f08", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("user_preferences", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("user_statuses", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("user_synced_attributes_metadata", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("users", "application_setting_terms", {:column=>"accepted_term_id", :name=>"fk_789cd90b35", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("users", "namespaces", {:column=>"managing_group_id", :name=>"fk_a4b8fefe3e", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0021s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("users_ops_dashboard_projects", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("users_ops_dashboard_projects", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("users_security_dashboard_projects", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0615s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("users_security_dashboard_projects", "users", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0022s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("users_star_projects", "projects", {:name=>"fk_22cd27ddfc", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0021s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "epics", {:name=>"fk_1d37cddf91", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "milestones", {:column=>"due_date_sourcing_milestone_id", :name=>"fk_7c5bb22a22", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "milestones", {:column=>"start_date_sourcing_milestone_id", :name=>"fk_88b4d546ef", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "milestones", {:name=>"fk_131d289c65", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "projects", {:name=>"fk_efb96ab1e2", :on_delete=>:cascade})

module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0043s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "users", {:column=>"author_id", :name=>"fk_b1de915a15", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "users", {:column=>"closed_by_id", :name=>"fk_cf5c60acbf", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "users", {:column=>"last_edited_by_id", :name=>"fk_1302949740", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "users", {:column=>"resolved_by_id", :name=>"fk_76bc5f5455", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerabilities", "users", {:column=>"updated_by_id", :name=>"fk_7ac31eacb9", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_feedback", "ci_pipelines", {:column=>"pipeline_id", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_feedback", "issues", {:on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_feedback", "merge_requests", {:name=>"fk_563ff1912e", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_feedback", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0020s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_feedback", "users", {:column=>"author_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_feedback", "users", {:column=>"comment_author_id", :name=>"fk_94f7c8a81e", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_identifiers", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_issue_links", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_issue_links", "vulnerabilities", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_occurrence_identifiers", "vulnerability_identifiers", {:column=>"identifier_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_occurrence_identifiers", "vulnerability_occurrences", {:column=>"occurrence_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_occurrence_pipelines", "ci_pipelines", {:column=>"pipeline_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_occurrence_pipelines", "vulnerability_occurrences", {:column=>"occurrence_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_occurrences", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0019s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_occurrences", "vulnerabilities", {:name=>"fk_97ffe77653", :on_delete=>:nullify})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0014s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_occurrences", "vulnerability_identifiers", {:column=>"primary_identifier_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0015s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_occurrences", "vulnerability_scanners", {:column=>"scanner_id", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0013s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("vulnerability_scanners", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0018s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("web_hook_logs", "web_hooks", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("web_hooks", "projects", {:name=>"fk_0c8ca6d9d1", :on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("zoom_meetings", "issues", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0017s
module.gitlab.aws_instance.gitlab[0] (remote-exec):               -- add_foreign_key("zoom_meetings", "projects", {:on_delete=>:cascade})
module.gitlab.aws_instance.gitlab[0] (remote-exec):                  -> 0.0016s

module.gitlab.aws_instance.gitlab[0] (remote-exec):               == Seed from /opt/gitlab/embedded/service/gitlab-rails/db/fixtures/production/001_application_settings.rb
module.gitlab.aws_instance.gitlab[0] (remote-exec):               Creating the default ApplicationSetting record.

module.gitlab.aws_instance.gitlab[0] (remote-exec):               == Seed from /opt/gitlab/embedded/service/gitlab-rails/db/fixtures/production/002_admin.rb
module.gitlab.aws_instance.gitlab[0] (remote-exec):               Administrator account created:

module.gitlab.aws_instance.gitlab[0] (remote-exec):               login:    root
module.gitlab.aws_instance.gitlab[0] (remote-exec):               password: You'll be prompted to create one on your first visit.


module.gitlab.aws_instance.gitlab[0] (remote-exec):               == Seed from /opt/gitlab/embedded/service/gitlab-rails/db/fixtures/production/010_settings.rb

module.gitlab.aws_instance.gitlab[0] (remote-exec):               == Seed from /opt/gitlab/embedded/service/gitlab-rails/db/fixtures/production/999_common_metrics.rb

module.gitlab.aws_instance.gitlab[0] (remote-exec):               == Seed from ee/db/fixtures/production/010_license.rb

module.gitlab.aws_instance.gitlab[0] (remote-exec):               == Seed from ee/db/fixtures/production/027_plans.rb

module.gitlab.aws_instance.gitlab[0] (remote-exec):               OK
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute "bash"  "/tmp/chef-script20200103-12696-qzh7r8"
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::gitlab-rails
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[clear the gitlab-rails cache] action run
module.gitlab.aws_instance.gitlab[0]: Still creating... [3m0s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +export prometheus_run_dir='/run/gitlab/unicorn'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -P -u git:git -U git:git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /usr/bin/env \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    current_pidfile=/opt/gitlab/var/unicorn/unicorn.pid \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    rails_app=gitlab-rails \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    user=git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    group=git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    environment=production \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    unicorn_rb=/var/opt/gitlab/gitlab-rails/etc/unicorn.rb \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    prometheus_multiproc_dir="${prometheus_run_dir}" \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    /opt/gitlab/embedded/bin/gitlab-unicorn-wrapper
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/unicorn/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/unicorn/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/unicorn/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/unicorn/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/unicorn/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/unicorn/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/unicorn/log/run from none to d50262
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/unicorn/log/run	2020-01-03 12:37:53.291934037 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/unicorn/log/.chef-run20200103-12696-151ddm4	2020-01-03 12:37:53.291934037 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/unicorn
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/unicorn/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/unicorn/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/unicorn/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/unicorn/config	2020-01-03 12:37:53.295934039 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/unicorn/.chef-config20200103-12696-6ifr57	2020-01-03 12:37:53.295934039 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_unicorn] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_unicorn
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_unicorn] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/unicorn/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/unicorn/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for unicorn service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/unicorn/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/unicorn/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/unicorn/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/unicorn/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/unicorn/control/t] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/unicorn/control/t
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/unicorn/control/t from none to 84b233
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/unicorn/control/t	2020-01-03 12:37:53.303934041 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/unicorn/control/.chef-t20200103-12696-10tmrbn	2020-01-03 12:37:53.303934041 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,4 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +echo "Received TERM from runit, sending to process group (-PID)"
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +kill -- -$(cat /opt/gitlab/service/unicorn/supervise/pid)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/unicorn] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/unicorn to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/unicorn/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/unicorn/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_unicorn] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for unicorn service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/control/t] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/unicorn] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/unicorn/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/unicorn] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/unicorn to /opt/gitlab/sv/unicorn
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for unicorn service socket] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for unicorn service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/unicorn/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_unicorn] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for unicorn service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/unicorn/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/unicorn/control/t] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/unicorn] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/unicorn/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/unicorn] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for unicorn service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/unicorn] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for unicorn service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start unicorn] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: unicorn: (pid 13568) 1s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start unicorn
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * consul_service[rails] action delete
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/var/opt/gitlab/consul/config.d/rails-service.json] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * gitlab_sysctl[net.core.somaxconn] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[create /etc/sysctl.d for net.core.somaxconn] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[create /opt/gitlab/embedded/etc/90-omnibus-gitlab-net.core.somaxconn.conf net.core.somaxconn] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/embedded/etc/90-omnibus-gitlab-net.core.somaxconn.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/embedded/etc/90-omnibus-gitlab-net.core.somaxconn.conf from none to 353a75
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/embedded/etc/90-omnibus-gitlab-net.core.somaxconn.conf	2020-01-03 12:37:59.271935528 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/embedded/etc/.chef-90-omnibus-gitlab-net20200103-12696-m5hzy4.core.somaxconn.conf	2020-01-03 12:37:59.271935528 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +net.core.somaxconn = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf net.core.somaxconn] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] * Applying /etc/sysctl.d/10-console-messages.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.printk = 4 4 1 7
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ipv6-privacy.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-kernel-hardening.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.kptr_restrict = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-link-restrictions.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_hardlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_symlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-lxd-inotify.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.inotify.max_user_instances = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-magic-sysrq.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sysrq = 176
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-network-security.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.default.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.tcp_syncookies = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ptrace.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.yama.ptrace_scope = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-zeropage.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 vm.mmap_min_addr = 65536
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /usr/lib/sysctl.d/50-default.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.promote_secondaries = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.core.default_qdisc = fq_codel
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.sem.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sem = 250 32000 32 262
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmall.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmall = 4194304
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmmax.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmmax = 17179869184
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-cloudimg-ipv6.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute sysctl -e --system
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/etc/sysctl.d/90-omnibus-gitlab-net.core.somaxconn.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /etc/sysctl.d/90-omnibus-gitlab-net.core.somaxconn.conf to /opt/gitlab/embedded/etc/90-omnibus-gitlab-net.core.somaxconn.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf net.core.somaxconn] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       [execute] * Applying /etc/sysctl.d/10-console-messages.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.printk = 4 4 1 7
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ipv6-privacy.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-kernel-hardening.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.kptr_restrict = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-link-restrictions.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_hardlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.protected_symlinks = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-lxd-inotify.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 fs.inotify.max_user_instances = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-magic-sysrq.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sysrq = 176
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-network-security.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.default.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.rp_filter = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.tcp_syncookies = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-ptrace.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.yama.ptrace_scope = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/10-zeropage.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 vm.mmap_min_addr = 65536
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /usr/lib/sysctl.d/50-default.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv4.conf.all.promote_secondaries = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.core.default_qdisc = fq_codel
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.sem.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.sem = 250 32000 32 262
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmall.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmall = 4194304
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-kernel.shmmax.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 kernel.shmmax = 17179869184
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/90-omnibus-gitlab-net.core.somaxconn.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.core.somaxconn = 1024
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-cloudimg-ipv6.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.all.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 net.ipv6.conf.default.use_tempaddr = 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.d/99-sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):                 * Applying /etc/sysctl.conf ...
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute sysctl -e --system
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * execute[load sysctl conf net.core.somaxconn] action nothing (skipped due to action :nothing)

module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[puma] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::puma_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[puma] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable puma] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * consul_service[rails] action delete (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/sidekiq] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'git'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[sidekiq] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[sidekiq] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/sidekiq] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/sidekiq/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/sidekiq/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/sidekiq/run from none to 09a7f9
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/sidekiq/run	2020-01-03 12:37:59.359935548 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/sidekiq/.chef-run20200103-12696-hbuj13	2020-01-03 12:37:59.359935548 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,26 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +cd /var/opt/gitlab/gitlab-rails/working
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Setup run directory.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +mkdir -p /run/gitlab/sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +rm /run/gitlab/sidekiq/*.db 2> /dev/null
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +chmod 0700 /run/gitlab/sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +chown git /run/gitlab/sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +export prometheus_run_dir='/run/gitlab/sidekiq'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -e /opt/gitlab/etc/gitlab-rails/env -P \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -U git:git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -u git:git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /usr/bin/env \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    prometheus_multiproc_dir="${prometheus_run_dir}" \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    /opt/gitlab/embedded/bin/bundle exec sidekiq \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +      -C /opt/gitlab/embedded/service/gitlab-rails/config/sidekiq_queues.yml \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +      -e production \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +      -r /opt/gitlab/embedded/service/gitlab-rails \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +      -t 4 \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +      -c 25
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/sidekiq/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/sidekiq/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/sidekiq/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/sidekiq/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/sidekiq/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/sidekiq/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/sidekiq/log/run from none to 0c55bd
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/sidekiq/log/run	2020-01-03 12:37:59.375935552 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/sidekiq/log/.chef-run20200103-12696-u7alip	2020-01-03 12:37:59.375935552 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd /var/log/gitlab/sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/sidekiq/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/sidekiq/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/sidekiq/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/sidekiq/config	2020-01-03 12:37:59.395935556 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/sidekiq/.chef-config20200103-12696-lqph4r	2020-01-03 12:37:59.395935556 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_sidekiq] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_sidekiq] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/sidekiq/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/sidekiq/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for sidekiq service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/sidekiq/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/sidekiq/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/sidekiq/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/sidekiq/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/sidekiq] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/sidekiq to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/sidekiq/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/sidekiq/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/sidekiq/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/sidekiq/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_sidekiq] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for sidekiq service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/sidekiq/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/sidekiq/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/sidekiq] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/sidekiq/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/sidekiq] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/sidekiq to /opt/gitlab/sv/sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for sidekiq service socket] action run
module.gitlab.aws_instance.gitlab[0]: Still creating... [3m20s elapsed]

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for sidekiq service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/sidekiq/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/sidekiq/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/sidekiq/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_sidekiq] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for sidekiq service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/sidekiq/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/sidekiq/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/sidekiq/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/sidekiq] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/sidekiq/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/sidekiq] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for sidekiq service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/sidekiq] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for sidekiq service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start sidekiq] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: sidekiq: (pid 13596) 1s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * consul_service[sidekiq] action delete
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/var/opt/gitlab/consul/config.d/sidekiq-service.json] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/gitlab-workhorse] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0750'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'git'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'gitlab-www'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/gitlab-workhorse] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'git'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/opt/gitlab/etc/gitlab-workhorse] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /opt/gitlab/etc/gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'git'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * env_dir[/opt/gitlab/etc/gitlab-workhorse/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/etc/gitlab-workhorse/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/etc/gitlab-workhorse/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/gitlab-workhorse/env/PATH] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/gitlab-workhorse/env/PATH
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/gitlab-workhorse/env/PATH from none to d5dc07
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/gitlab-workhorse/env/PATH	2020-01-03 12:38:05.523936852 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/gitlab-workhorse/env/.chef-PATH20200103-12696-vvj3s4	2020-01-03 12:38:05.523936852 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/opt/gitlab/bin:/opt/gitlab/embedded/bin:/bin:/usr/bin
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/gitlab-workhorse/env/HOME] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/gitlab-workhorse/env/HOME
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/gitlab-workhorse/env/HOME from none to 205bb9
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/gitlab-workhorse/env/HOME	2020-01-03 12:38:05.527936853 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/gitlab-workhorse/env/.chef-HOME20200103-12696-yu1a8u	2020-01-03 12:38:05.527936853 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/var/opt/gitlab
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/gitlab-workhorse/env/SSL_CERT_DIR] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/gitlab-workhorse/env/SSL_CERT_DIR
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/gitlab-workhorse/env/SSL_CERT_DIR from none to 4f45cf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/gitlab-workhorse/env/SSL_CERT_DIR	2020-01-03 12:38:05.531936854 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/gitlab-workhorse/env/.chef-SSL_CERT_DIR20200103-12696-y6812l	2020-01-03 12:38:05.531936854 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/opt/gitlab/embedded/ssl/certs/
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[gitlab-workhorse] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[gitlab-workhorse] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-workhorse] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/gitlab-workhorse/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/gitlab-workhorse/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/gitlab-workhorse/run from none to a979e8
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/gitlab-workhorse/run	2020-01-03 12:38:05.563936860 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/gitlab-workhorse/.chef-run20200103-12696-1gp2i4b	2020-01-03 12:38:05.563936860 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,28 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +set -e # fail on errors
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Redirect stderr -> stdout
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +cd /var/opt/gitlab/gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -e /opt/gitlab/etc/gitlab-workhorse/env -P \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -U git:git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -u git:git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /opt/gitlab/embedded/bin/gitlab-workhorse \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -listenNetwork unix \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -listenUmask 0 \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -listenAddr /var/opt/gitlab/gitlab-workhorse/socket \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -authBackend http://localhost:8080 \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -authSocket /var/opt/gitlab/gitlab-rails/sockets/gitlab.socket \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -documentRoot /opt/gitlab/embedded/service/gitlab-rails/public \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -pprofListenAddr ''\
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -prometheusListenAddr localhost:9229 \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -secretPath /opt/gitlab/embedded/service/gitlab-rails/.gitlab_workhorse_secret \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -logFormat json \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -config config.toml \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +# Do not remove this line; it prevents trouble with the trailing backslashes above.
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-workhorse/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-workhorse/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-workhorse/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-workhorse/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/gitlab-workhorse/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/gitlab-workhorse/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/gitlab-workhorse/log/run from none to 34ab60
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/gitlab-workhorse/log/run	2020-01-03 12:38:05.591936866 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/gitlab-workhorse/log/.chef-run20200103-12696-iabzer	2020-01-03 12:38:05.591936866 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd /var/log/gitlab/gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/gitlab-workhorse/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/gitlab-workhorse/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/gitlab-workhorse/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/gitlab-workhorse/config	2020-01-03 12:38:05.599936867 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/gitlab-workhorse/.chef-config20200103-12696-104ckkr	2020-01-03 12:38:05.599936867 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_gitlab-workhorse] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_gitlab-workhorse] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-workhorse/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-workhorse/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for gitlab-workhorse service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/gitlab-workhorse/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/gitlab-workhorse/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-workhorse/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-workhorse/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/gitlab-workhorse] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/gitlab-workhorse to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/gitlab-workhorse/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-workhorse/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-workhorse/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/gitlab-workhorse/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_gitlab-workhorse] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for gitlab-workhorse service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-workhorse/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-workhorse/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/gitlab-workhorse] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/gitlab-workhorse/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/gitlab-workhorse] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/gitlab-workhorse to /opt/gitlab/sv/gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for gitlab-workhorse service socket] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for gitlab-workhorse service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-workhorse/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-workhorse/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/gitlab-workhorse/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_gitlab-workhorse] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for gitlab-workhorse service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-workhorse/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-workhorse/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-workhorse/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/gitlab-workhorse] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/gitlab-workhorse/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/gitlab-workhorse] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for gitlab-workhorse service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/gitlab-workhorse] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for gitlab-workhorse service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * consul_service[workhorse] action delete
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/var/opt/gitlab/consul/config.d/workhorse-service.json] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[/var/opt/gitlab/gitlab-workhorse/VERSION] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/gitlab-workhorse/VERSION
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/gitlab-workhorse/VERSION from none to f8b727
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/gitlab-workhorse/VERSION2020-01-03 12:38:10.867937827 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/gitlab-workhorse/.chef-VERSION20200103-12696-4k121i	2020-01-03 12:38:10.867937827 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +gitlab-workhorse v8.18.0-20191220.103235
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/gitlab-workhorse/config.toml] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/gitlab-workhorse/config.toml
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/gitlab-workhorse/config.toml from none to cb62fe
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/gitlab-workhorse/config.toml	2020-01-03 12:38:10.871937829 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/gitlab-workhorse/.chef-config20200103-12696-146gky1.toml	2020-01-03 12:38:10.871937829 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,4 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[redis]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +URL = "unix:/var/opt/gitlab/redis/redis.socket"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +Password = ""
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0640'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'git'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[mailroom] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::mailroom_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[mailroom] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable mailroom] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/nginx] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0750'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'gitlab-www'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/nginx/conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/nginx/conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0750'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'gitlab-www'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/nginx] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0750'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'gitlab-www'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * link[/var/opt/gitlab/nginx/logs] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create symlink at /var/opt/gitlab/nginx/logs to /var/log/gitlab/nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/nginx/conf/gitlab-http.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/nginx/conf/gitlab-http.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/nginx/conf/gitlab-http.conf from none to d96ee8
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/nginx/conf/gitlab-http.conf	2020-01-03 12:38:10.899937833 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/nginx/conf/.chef-gitlab-http20200103-12696-fmhmwa.conf	2020-01-03 12:38:10.899937833 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,125 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# This file is managed by gitlab-ctl. Manual changes will be
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# and run `sudo gitlab-ctl reconfigure`.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## GitLab
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## Modified from https://gitlab.com/gitlab-org/gitlab-foss/blob/master/lib/support/nginx/gitlab-ssl & https://gitlab.com/gitlab-org/gitlab-foss/blob/master/lib/support/nginx/gitlab
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## Lines starting with two hashes (##) are comments with information.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## Lines starting with one hash (#) are configuration parameters that can be uncommented.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##        CHUNKED TRANSFER      ##
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## It is a known issue that Git-over-HTTP requires chunked transfer encoding [0]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## which is not supported by Nginx < 1.3.9 [1]. As a result, pushing a large object
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## with Git (i.e. a single large file) can lead to a 411 error. In theory you can get
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## around this by tweaking this configuration file and either:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## - installing an old version of Nginx with the chunkin module [2] compiled in, or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## - using a newer version of Nginx.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## At the time of writing we do not know if either of these theoretical solutions works.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## As a workaround users can use Git over SSH to push large files.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## [0] https://git.kernel.org/cgit/git/git.git/tree/Documentation/technical/http-protocol.txt#n99
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## [1] https://github.com/agentzh/chunkin-nginx-module#status
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +## [2] https://github.com/agentzh/chunkin-nginx-module
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +###################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##         configuration         ##
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +###################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +server {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  listen *:80;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  server_name tfe-ssc-3-gitlab.guselietov.com;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  server_tokens off; ## Don't show the nginx version number, a security best practice
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ## Increase this if you want to upload large attachments
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ## Or if you want to accept large git objects over http
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  client_max_body_size 0;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ## Real IP Module Config
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ## http://nginx.org/en/docs/http/ngx_http_realip_module.html
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ## HSTS Config
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ## https://www.nginx.com/blog/http-strict-transport-security-hsts-and-nginx/
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  add_header Strict-Transport-Security "max-age=31536000";
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  add_header Referrer-Policy strict-origin-when-cross-origin;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ## Individual nginx logs for this GitLab vhost
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  access_log  /var/log/gitlab/nginx/gitlab_access.log gitlab_access;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  error_log   /var/log/gitlab/nginx/gitlab_error.log;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  if ($http_host = "") {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    set $http_host_with_default "tfe-ssc-3-gitlab.guselietov.com";
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  if ($http_host != "") {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    set $http_host_with_default $http_host;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip on;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_static on;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_comp_level 2;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_http_version 1.1;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_vary on;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_disable "msie6";
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_min_length 10240;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_proxied no-cache no-store private expired auth;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/json application/xml application/rss+xml;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ## https://github.com/gitlabhq/gitlabhq/issues/694
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ## Some requests take more than 30 seconds.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_read_timeout      3600;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_connect_timeout   300;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_redirect          off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_http_version 1.1;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_set_header Host $http_host_with_default;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_set_header X-Real-IP $remote_addr;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_set_header Upgrade $http_upgrade;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_set_header Connection $connection_upgrade;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_set_header X-Forwarded-Proto http;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  location ~ (.git/git-receive-pack$|.git/info/refs?service=git-receive-pack$|.git/gitlab-lfs/objects|.git/info/lfs/objects/batch$) {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    proxy_cache off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    proxy_pass http://gitlab-workhorse;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    proxy_request_buffering off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  location /-/grafana/ {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    proxy_pass http://localhost:3000/;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # health checks configuration
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  include /var/opt/gitlab/nginx/conf/gitlab-health.conf;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  location / {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    proxy_cache off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    proxy_pass  http://gitlab-workhorse;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  location /assets {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    proxy_cache gitlab;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    proxy_pass  http://gitlab-workhorse;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  error_page 404 /404.html;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  error_page 500 /500.html;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  error_page 502 /502.html;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  location ~ ^/(404|500|502)(-custom)?\.html$ {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    root /opt/gitlab/embedded/service/gitlab-rails/public;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    internal;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/nginx/conf/gitlab-smartcard-http.conf] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/nginx/conf/gitlab-health.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/nginx/conf/gitlab-health.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/nginx/conf/gitlab-health.conf from none to 92d04b
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/nginx/conf/gitlab-health.conf	2020-01-03 12:38:10.939937840 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/nginx/conf/.chef-gitlab-health20200103-12696-6jb025.conf	2020-01-03 12:38:10.939937840 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,30 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# This file is managed by gitlab-ctl. Manual changes will be
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# and run `sudo gitlab-ctl reconfigure`.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +location /error.txt {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # return code here is ignored by the error_page directive
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  return 500 'nginx returned $status when communicating with gitlab-workhorse\n';
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +location /error.json  {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # return code here is ignored by the error_page directive
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  return 500 '{"error":"nginx returned $status when communicating with gitlab-workhorse","status":$status}\n';
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +location = /-/health {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_cache off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_pass  http://gitlab-workhorse;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  error_page 404 500 502 /error.txt;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +location = /-/readiness {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_cache off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_pass  http://gitlab-workhorse;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  error_page 404 500 502 /error.json;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +location = /-/liveness {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_cache off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_pass  http://gitlab-workhorse;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  error_page 404 500 502 /error.json;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/nginx/conf/gitlab-pages.conf] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/nginx/conf/gitlab-registry.conf] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/nginx/conf/gitlab-mattermost-http.conf] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/nginx/conf/nginx-status.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/nginx/conf/nginx-status.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/nginx/conf/nginx-status.conf from none to 74440c
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/nginx/conf/nginx-status.conf	2020-01-03 12:38:10.959937844 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/nginx/conf/.chef-nginx-status20200103-12696-1er7jdk.conf	2020-01-03 12:38:10.959937844 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,29 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +server  {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    listen *:8060;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    server_name localhost;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    location /nginx_status {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      stub_status;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      server_tokens off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      access_log off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      allow 127.0.0.1;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      deny all;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    location /metrics {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      vhost_traffic_status_display;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      vhost_traffic_status_display_format prometheus;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      server_tokens off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      access_log off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      allow 127.0.0.1;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      deny all;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    location /rails-metrics {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      proxy_cache off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      proxy_pass  http://gitlab-workhorse/-/metrics;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      server_tokens off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      access_log off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      allow 127.0.0.1;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      deny all;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * consul_service[nginx] action delete
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/var/opt/gitlab/consul/config.d/nginx-service.json] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/nginx/conf/nginx.conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/nginx/conf/nginx.conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/nginx/conf/nginx.conf from none to a7c979
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/nginx/conf/nginx.conf	2020-01-03 12:38:10.971937846 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/nginx/conf/.chef-nginx20200103-12696-2kec55.conf	2020-01-03 12:38:10.971937846 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,91 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# This file is managed by gitlab-ctl. Manual changes will be
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# and run `sudo gitlab-ctl reconfigure`.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +user gitlab-www gitlab-www;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +worker_processes 2;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +error_log stderr;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pid nginx.pid;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +daemon off;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +events {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  worker_connections 10240;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +http {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  log_format gitlab_access '$remote_addr - $remote_user [$time_local] "$request_method $filtered_request_uri $server_protocol" $status $body_bytes_sent "$filtered_http_referer" "$http_user_agent"';
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  log_format gitlab_mattermost_access '$remote_addr - $remote_user [$time_local] "$request_method $filtered_request_uri $server_protocol" $status $body_bytes_sent "$filtered_http_referer" "$http_user_agent"';
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  server_names_hash_bucket_size 64;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  sendfile on;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  tcp_nopush on;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  tcp_nodelay on;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  keepalive_timeout 65;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip on;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_http_version 1.0;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_comp_level 2;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_proxied any;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  gzip_types text/plain text/css application/x-javascript text/xml application/xml application/xml+rss text/javascript application/json;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  include /opt/gitlab/embedded/conf/mime.types;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_cache_path proxy_cache keys_zone=gitlab:10m max_size=1g levels=1:2;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  proxy_cache gitlab;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  map $http_upgrade $connection_upgrade {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      default upgrade;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ''      close;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Remove private_token from the request URI
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # In:  /foo?private_token=unfiltered&authenticity_token=unfiltered&rss_token=unfiltered&...
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Out: /foo?private_token=[FILTERED]&authenticity_token=unfiltered&rss_token=unfiltered&...
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  map $request_uri $temp_request_uri_1 {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    default $request_uri;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    ~(?i)^(?<start>.*)(?<temp>[\?&]private[\-_]token)=[^&]*(?<rest>.*)$ "$start$temp=[FILTERED]$rest";
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Remove authenticity_token from the request URI
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # In:  /foo?private_token=[FILTERED]&authenticity_token=unfiltered&rss_token=unfiltered&...
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Out: /foo?private_token=[FILTERED]&authenticity_token=[FILTERED]&rss_token=unfiltered&...
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  map $temp_request_uri_1 $temp_request_uri_2 {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    default $temp_request_uri_1;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    ~(?i)^(?<start>.*)(?<temp>[\?&]authenticity[\-_]token)=[^&]*(?<rest>.*)$ "$start$temp=[FILTERED]$rest";
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Remove rss_token from the request URI
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # In:  /foo?private_token=[FILTERED]&authenticity_token=[FILTERED]&rss_token=unfiltered&...
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Out: /foo?private_token=[FILTERED]&authenticity_token=[FILTERED]&rss_token=[FILTERED]&...
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  map $temp_request_uri_2 $filtered_request_uri {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    default $temp_request_uri_2;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    ~(?i)^(?<start>.*)(?<temp>[\?&]rss[\-_]token)=[^&]*(?<rest>.*)$ "$start$temp=[FILTERED]$rest";
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # A version of the referer without the query string
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  map $http_referer $filtered_http_referer {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    default $http_referer;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    ~^(?<temp>.*)\? $temp;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Enable vts status module.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  vhost_traffic_status_zone;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  upstream gitlab-workhorse {
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    server unix:/var/opt/gitlab/gitlab-workhorse/socket;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  }
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  include /var/opt/gitlab/nginx/conf/gitlab-http.conf;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  include /var/opt/gitlab/nginx/conf/nginx-status.conf;
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[nginx] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: nginx::enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[nginx] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/nginx] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/nginx/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/nginx/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/nginx/run from none to d75aea
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/nginx/run	2020-01-03 12:38:10.999937851 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/nginx/.chef-run20200103-12696-1y6i0l1	2020-01-03 12:38:10.999937851 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,6 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +cd /var/opt/gitlab/nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -P /opt/gitlab/embedded/sbin/nginx -p /var/opt/gitlab/nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/nginx/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/nginx/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/nginx/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/nginx/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/nginx/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/nginx/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/nginx/log/run from none to c70025
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/nginx/log/run	2020-01-03 12:38:11.019937854 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/nginx/log/.chef-run20200103-12696-1os8h34	2020-01-03 12:38:11.019937854 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/nginx/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/nginx/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/nginx/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/nginx/config	2020-01-03 12:38:11.027937855 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/nginx/.chef-config20200103-12696-dytvcd	2020-01-03 12:38:11.027937855 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_nginx] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_nginx] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/nginx/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/nginx/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for nginx service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/nginx/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/nginx/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/nginx/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/nginx/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/nginx] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/nginx to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/nginx/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/nginx/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/nginx/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/nginx/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_nginx] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for nginx service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/nginx/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/nginx/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/nginx] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/nginx/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/nginx] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/nginx to /opt/gitlab/sv/nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for nginx service socket] action run
module.gitlab.aws_instance.gitlab[0]: Still creating... [3m30s elapsed]

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for nginx service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/nginx/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/nginx/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/nginx/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_nginx] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for nginx service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/nginx/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/nginx/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/nginx/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/nginx] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/nginx/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/nginx] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for nginx service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/nginx] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for nginx service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[reload nginx] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start nginx] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: nginx: (pid 13636) 3s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[remote-syslog] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::remote-syslog_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[remote-syslog] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable remote-syslog] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[logrotate] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::logrotate
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[logrotate] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/logrotate] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/logrotate
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/logrotate/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/logrotate/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/logrotate/run from none to 07f1b6
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/logrotate/run	2020-01-03 12:38:15.415938561 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/logrotate/.chef-run20200103-12696-912tsk	2020-01-03 12:38:15.415938561 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,11 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +cd /var/opt/gitlab/logrotate
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec /opt/gitlab/embedded/bin/chpst -P /usr/bin/env \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  dir=/var/opt/gitlab/logrotate \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  pre_sleep=600 \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  post_sleep=3000 \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /opt/gitlab/embedded/bin/gitlab-logrotate-wrapper
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/logrotate/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/logrotate/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/logrotate/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/logrotate/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/logrotate/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/logrotate/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/logrotate/log/run from none to 94afe6
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/logrotate/log/run	2020-01-03 12:38:15.431938563 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/logrotate/log/.chef-run20200103-12696-1accvqf	2020-01-03 12:38:15.431938563 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/logrotate
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/logrotate/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/logrotate/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/logrotate/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/logrotate/config	2020-01-03 12:38:15.435938564 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/logrotate/.chef-config20200103-12696-43jkwa	2020-01-03 12:38:15.435938564 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_logrotate] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_logrotate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_logrotate] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/logrotate/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/logrotate/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for logrotate service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/logrotate/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/logrotate/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/logrotate/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/logrotate/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/logrotate/control/t] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/logrotate/control/t
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/logrotate/control/t from none to 8fa3fa
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/logrotate/control/t	2020-01-03 12:38:15.455938567 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/logrotate/control/.chef-t20200103-12696-ulgy2b	2020-01-03 12:38:15.455938567 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,4 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +echo "Received TERM from runit, sending to process group (-PID)"
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +kill -- -$(cat /opt/gitlab/service/logrotate/supervise/pid)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/logrotate] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/logrotate to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/logrotate/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/logrotate/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_logrotate] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for logrotate service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/control/t] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/logrotate] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/logrotate/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/logrotate] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/logrotate to /opt/gitlab/sv/logrotate
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for logrotate service socket] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for logrotate service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/logrotate/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_logrotate] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for logrotate service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/logrotate/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/logrotate/control/t] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/logrotate] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/logrotate/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/logrotate] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for logrotate service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/logrotate] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for logrotate service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start logrotate] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: logrotate: (pid 13657) 1s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start logrotate
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::bootstrap
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[/var/opt/gitlab/bootstrapped] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/bootstrapped
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/bootstrapped from none to 4ae00c
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/bootstrapped	2020-01-03 12:38:19.475939152 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/.chef-bootstrapped20200103-12696-1ehvj7y	2020-01-03 12:38:19.475939152 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +All your bootstraps are belong to Chef
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0600'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[gitlab-pages] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::gitlab-pages_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[gitlab-pages] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable gitlab-pages] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[storage-check] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::storage-check_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[storage-check] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable storage-check] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[registry] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: registry::disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[registry] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable registry] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[mattermost] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: mattermost::disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[mattermost] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable mattermost] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::gitlab-healthcheck
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/opt/gitlab/etc/gitlab-healthcheck-rc] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /opt/gitlab/etc/gitlab-healthcheck-rc
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /opt/gitlab/etc/gitlab-healthcheck-rc from none to 6da55f
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /opt/gitlab/etc/gitlab-healthcheck-rc	2020-01-03 12:38:19.495939154 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /opt/gitlab/etc/.chef-gitlab-healthcheck-rc20200103-12696-1xojjle	2020-01-03 12:38:19.495939154 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +url='http://localhost:80/help'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +flags='--insecure'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::user
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * account[Prometheus user and group] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * group[Prometheus user and group] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create group gitlab-prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * linux_user[Prometheus user and group] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create user gitlab-prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::node-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/node-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/node-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/opt/gitlab/etc/node-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /opt/gitlab/etc/node-exporter/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * env_dir[/opt/gitlab/etc/node-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/etc/node-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/node-exporter/env/SSL_CERT_DIR] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/node-exporter/env/SSL_CERT_DIR
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/node-exporter/env/SSL_CERT_DIR from none to 4f45cf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/node-exporter/env/SSL_CERT_DIR	2020-01-03 12:38:19.659939177 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/node-exporter/env/.chef-SSL_CERT_DIR20200103-12696-ylq0mh	2020-01-03 12:38:19.659939177 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/opt/gitlab/embedded/ssl/certs/
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/node-exporter/textfile_collector] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/node-exporter/textfile_collector
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[node-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::node-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[node-exporter] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/node-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/node-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/node-exporter/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/node-exporter/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/node-exporter/run from none to 744544
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/node-exporter/run	2020-01-03 12:38:19.687939181 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/node-exporter/.chef-run20200103-12696-r8ttec	2020-01-03 12:38:19.687939181 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,9 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +umask 077
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -P -e /opt/gitlab/etc/node-exporter/env \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -U gitlab-prometheus:gitlab-prometheus \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -u gitlab-prometheus:gitlab-prometheus \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /opt/gitlab/embedded/bin/node_exporter --web.listen-address=localhost:9100 --collector.mountstats --collector.runit --collector.runit.servicedir=/opt/gitlab/sv --collector.textfile.directory=/var/opt/gitlab/node-exporter/textfile_collector
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/node-exporter/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/node-exporter/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/node-exporter/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/node-exporter/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/node-exporter/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/node-exporter/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/node-exporter/log/run from none to ae1796
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/node-exporter/log/run	2020-01-03 12:38:19.707939184 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/node-exporter/log/.chef-run20200103-12696-1kqede9	2020-01-03 12:38:19.707939184 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/node-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/node-exporter/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/node-exporter/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/node-exporter/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/node-exporter/config	2020-01-03 12:38:19.715939184 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/node-exporter/.chef-config20200103-12696-bixejr	2020-01-03 12:38:19.715939184 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_node-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_node-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_node-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/node-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/node-exporter/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for node-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/node-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/node-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/node-exporter/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/node-exporter/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/node-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/node-exporter to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/node-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/node-exporter/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/node-exporter/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/node-exporter/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_node-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for node-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/node-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/node-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/node-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/node-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/node-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/node-exporter to /opt/gitlab/sv/node-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for node-exporter service socket] action run
module.gitlab.aws_instance.gitlab[0]: Still creating... [3m40s elapsed]

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for node-exporter service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/node-exporter/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/node-exporter/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/node-exporter/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_node-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for node-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/node-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/node-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/node-exporter/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/node-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/node-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/node-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for node-exporter service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/node-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for node-exporter service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start node-exporter] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: node-exporter: (pid 13690) 1s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start node-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * consul_service[node-exporter] action delete
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/var/opt/gitlab/consul/config.d/node-exporter-service.json] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/gitlab-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'git'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[gitlab-monitor] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[gitlab-monitor] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable gitlab-monitor] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/gitlab-monitor] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/gitlab-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'git'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/gitlab-exporter/gitlab-exporter.yml] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/gitlab-exporter/gitlab-exporter.yml
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/gitlab-exporter/gitlab-exporter.yml from none to 9b080d
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/gitlab-exporter/gitlab-exporter.yml	2020-01-03 12:38:25.847939974 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/gitlab-exporter/.chef-gitlab-exporter20200103-12696-19mhhni.yml	2020-01-03 12:38:25.847939974 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,75 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +db_common: &db_common
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  methods:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - probe_db
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  opts:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    connection_string: dbname=gitlabhq_production user=gitlab host=/var/opt/gitlab/postgresql port=5432 password=
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Web server config
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +server:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  listen_address: localhost
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  listen_port: 9168
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Probes config
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +probes:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  git_process: &git_process
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    class_name: GitProcessProber # `class_name` is redundant here
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    methods:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - probe_git
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    opts:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      quantiles: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # We can group multiple probes under a single endpoint by setting the `multiple` key to `true`, followed
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # by probe definitions as usual.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  database:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    multiple: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    ci_builds:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      class_name: Database::CiBuildsProber
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      <<: *db_common
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    tuple_stats:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      class_name: Database::TuplesProber
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      <<: *db_common
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    rows_count:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      class_name: Database::RowCountProber
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      <<: *db_common
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  process: &process
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    methods:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - probe_stat
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - probe_count
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    opts:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - pid_or_pattern: "sidekiq .* \\[.*?\\]"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        name: sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - pid_or_pattern: "unicorn.* worker\\[.*?\\]"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        name: unicorn
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - pid_or_pattern: "git-upload-pack --stateless-rpc"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        name: git_upload_pack
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        quantiles: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  sidekiq: &sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    methods:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - probe_stats
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - probe_queues
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - probe_workers
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - probe_retries
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    opts:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      redis_url: "unix:/var/opt/gitlab/redis/redis.socket"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      redis_enable_client: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    multiple: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    git_process:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      <<: *git_process
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    process:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      <<: *process
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    sidekiq:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      <<: *sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    ci_builds:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      class_name: Database::CiBuildsProber
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      <<: *db_common
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    tuple_stats:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      class_name: Database::TuplesProber
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      <<: *db_common
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    rows_count:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      class_name: Database::RowCountProber
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      <<: *db_common
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0600'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'git'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[/var/opt/gitlab/gitlab-exporter/RUBY_VERSION] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/gitlab-exporter/RUBY_VERSION
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/gitlab-exporter/RUBY_VERSION from none to e43343
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/gitlab-exporter/RUBY_VERSION	2020-01-03 12:38:25.867939976 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/gitlab-exporter/.chef-RUBY_VERSION20200103-12696-k50b3m	2020-01-03 12:38:25.867939976 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +ruby 2.6.3p62 (2019-04-16 revision 67580) [x86_64-linux]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[gitlab-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[gitlab-exporter] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/gitlab-exporter/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/gitlab-exporter/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/gitlab-exporter/run from none to 4072c9
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/gitlab-exporter/run	2020-01-03 12:38:25.887939979 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/gitlab-exporter/.chef-run20200103-12696-xddupd	2020-01-03 12:38:25.887939979 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,10 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +umask 077
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -P \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -U git:git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -u git:git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /opt/gitlab/embedded/bin/gitlab-exporter web \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +    -c /var/opt/gitlab/gitlab-exporter/gitlab-exporter.yml
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-exporter/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-exporter/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-exporter/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-exporter/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/gitlab-exporter/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/gitlab-exporter/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/gitlab-exporter/log/run from none to 690ab7
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/gitlab-exporter/log/run2020-01-03 12:38:25.907939981 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/gitlab-exporter/log/.chef-run20200103-12696-15q77yd	2020-01-03 12:38:25.907939981 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/gitlab-exporter/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/gitlab-exporter/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/gitlab-exporter/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/gitlab-exporter/config2020-01-03 12:38:25.915939982 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/gitlab-exporter/.chef-config20200103-12696-1t2sumg	2020-01-03 12:38:25.915939982 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_gitlab-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_gitlab-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-exporter/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for gitlab-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/gitlab-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/gitlab-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/gitlab-exporter/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/gitlab-exporter/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/gitlab-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/gitlab-exporter to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/gitlab-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-exporter/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-exporter/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/gitlab-exporter/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_gitlab-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for gitlab-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/gitlab-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/gitlab-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/gitlab-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/gitlab-exporter to /opt/gitlab/sv/gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for gitlab-exporter service socket] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for gitlab-exporter service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0]: Still creating... [3m50s elapsed]
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-exporter/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-exporter/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/gitlab-exporter/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_gitlab-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for gitlab-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/gitlab-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/gitlab-exporter/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/gitlab-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/gitlab-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/gitlab-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for gitlab-exporter service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/gitlab-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for gitlab-exporter service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start gitlab-exporter] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: gitlab-exporter: (pid 13708) 3s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start gitlab-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::redis-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/redis-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/redis-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-redis'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/opt/gitlab/etc/redis-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /opt/gitlab/etc/redis-exporter/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-redis'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * env_dir[/opt/gitlab/etc/redis-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/etc/redis-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/redis-exporter/env/SSL_CERT_DIR] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/redis-exporter/env/SSL_CERT_DIR
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/redis-exporter/env/SSL_CERT_DIR from none to 4f45cf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/redis-exporter/env/SSL_CERT_DIR	2020-01-03 12:38:33.219940792 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/redis-exporter/env/.chef-SSL_CERT_DIR20200103-12696-uqkupf	2020-01-03 12:38:33.219940792 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/opt/gitlab/embedded/ssl/certs/
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[redis-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::redis-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[redis-exporter] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/redis-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/redis-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/redis-exporter/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/redis-exporter/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/redis-exporter/run from none to a21d3f
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/redis-exporter/run	2020-01-03 12:38:33.251940795 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/redis-exporter/.chef-run20200103-12696-19fojx2	2020-01-03 12:38:33.251940795 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,9 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +umask 077
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -P -e /opt/gitlab/etc/redis-exporter/env \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -U gitlab-redis:git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -u gitlab-redis:git \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /opt/gitlab/embedded/bin/redis_exporter --web.listen-address=localhost:9121 --redis.addr=unix:///var/opt/gitlab/redis/redis.socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/redis-exporter/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/redis-exporter/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/redis-exporter/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/redis-exporter/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/redis-exporter/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/redis-exporter/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/redis-exporter/log/run from none to 082dea
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/redis-exporter/log/run2020-01-03 12:38:33.279940798 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/redis-exporter/log/.chef-run20200103-12696-1kunlw1	2020-01-03 12:38:33.279940798 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/redis-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/redis-exporter/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/redis-exporter/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/redis-exporter/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/redis-exporter/config2020-01-03 12:38:33.291940800 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/redis-exporter/.chef-config20200103-12696-18g36zy	2020-01-03 12:38:33.291940800 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_redis-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_redis-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_redis-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/redis-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/redis-exporter/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for redis-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/redis-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/redis-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/redis-exporter/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/redis-exporter/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/redis-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/redis-exporter to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/redis-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/redis-exporter/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/redis-exporter/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/redis-exporter/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_redis-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for redis-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/redis-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/redis-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/redis-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/redis-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/redis-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/redis-exporter to /opt/gitlab/sv/redis-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for redis-exporter service socket] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for redis-exporter service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/redis-exporter/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/redis-exporter/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/redis-exporter/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_redis-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for redis-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/redis-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/redis-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/redis-exporter/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/redis-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/redis-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/redis-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for redis-exporter service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/redis-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for redis-exporter service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start redis-exporter] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: redis-exporter: (pid 13726) 3s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start redis-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * consul_service[redis-exporter] action delete
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/var/opt/gitlab/consul/config.d/redis-exporter-service.json] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/prometheus] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0750'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/prometheus/rules] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/prometheus/rules
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0750'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/prometheus] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/opt/gitlab/etc/prometheus/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /opt/gitlab/etc/prometheus/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * env_dir[/opt/gitlab/etc/prometheus/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/etc/prometheus/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/prometheus/env/SSL_CERT_DIR] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/prometheus/env/SSL_CERT_DIR
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/prometheus/env/SSL_CERT_DIR from none to 4f45cf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/prometheus/env/SSL_CERT_DIR	2020-01-03 12:38:39.635941412 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/prometheus/env/.chef-SSL_CERT_DIR20200103-12696-84rwe	2020-01-03 12:38:39.635941412 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/opt/gitlab/embedded/ssl/certs/
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[reload prometheus] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[Prometheus config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/prometheus/prometheus.yml
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/prometheus/prometheus.yml from none to 526426
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/prometheus/prometheus.yml	2020-01-03 12:38:39.639941412 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/prometheus/.chef-prometheus20200103-12696-10izccq.yml	2020-01-03 12:38:39.639941412 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,171 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +---
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +global:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  scrape_interval: 15s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  scrape_timeout: 15s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +remote_read: []
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +remote_write: []
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +rule_files:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- "/var/opt/gitlab/prometheus/rules/*.rules"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +scrape_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:9090
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: nginx
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:8060
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: redis
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:9121
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: postgres
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:9187
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: node
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:9100
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:9229
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: gitlab-rails
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics_path: "/-/metrics"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - 127.0.0.1:8080
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  relabel_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __address__
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: 127.0.0.1:(.*)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    replacement: localhost:$1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: instance
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: gitlab-sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - 127.0.0.1:8082
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  relabel_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __address__
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: 127.0.0.1:(.*)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    replacement: localhost:$1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: instance
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: gitlab_exporter_database
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics_path: "/database"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:9168
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: gitlab_exporter_sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics_path: "/sidekiq"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:9168
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: gitlab_exporter_process
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics_path: "/process"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:9168
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: gitaly
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - localhost:9236
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: kubernetes-cadvisor
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  scheme: https
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  tls_config:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    insecure_skip_verify: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  bearer_token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  kubernetes_sd_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - role: node
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    api_server: https://kubernetes.default.svc:443
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    tls_config:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    bearer_token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  relabel_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - action: labelmap
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: __meta_kubernetes_node_label_(.+)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - target_label: __address__
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    replacement: kubernetes.default.svc:443
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __meta_kubernetes_node_name
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: "(.+)"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: __metrics_path__
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    replacement: "/api/v1/nodes/${1}/proxy/metrics/cadvisor"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metric_relabel_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - pod_name
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: environment
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: "(.+)-.+-.+"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: kubernetes-nodes
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  scheme: https
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  tls_config:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    insecure_skip_verify: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  bearer_token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  kubernetes_sd_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - role: node
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    api_server: https://kubernetes.default.svc:443
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    tls_config:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    bearer_token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  relabel_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - action: labelmap
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: __meta_kubernetes_node_label_(.+)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - target_label: __address__
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    replacement: kubernetes.default.svc:443
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __meta_kubernetes_node_name
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: "(.+)"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: __metrics_path__
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    replacement: "/api/v1/nodes/${1}/proxy/metrics"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metric_relabel_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - pod_name
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: environment
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: "(.+)-.+-.+"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- job_name: kubernetes-pods
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  tls_config:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    insecure_skip_verify: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  bearer_token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  kubernetes_sd_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - role: pod
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    api_server: https://kubernetes.default.svc:443
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    tls_config:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ca_file: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    bearer_token_file: "/var/run/secrets/kubernetes.io/serviceaccount/token"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  relabel_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __meta_kubernetes_pod_annotation_prometheus_io_scrape
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    action: keep
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: 'true'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __meta_kubernetes_pod_annotation_prometheus_io_path
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    action: replace
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: __metrics_path__
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: "(.+)"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __address__
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __meta_kubernetes_pod_annotation_prometheus_io_port
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    action: replace
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: "([^:]+)(?::[0-9]+)?;([0-9]+)"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    replacement: "$1:$2"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: __address__
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - action: labelmap
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    regex: __meta_kubernetes_pod_label_(.+)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __meta_kubernetes_namespace
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    action: replace
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: kubernetes_namespace
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - source_labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - __meta_kubernetes_pod_name
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    action: replace
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    target_label: kubernetes_pod_name
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +alerting:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  alertmanagers:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - static_configs:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - targets:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      - localhost:9093
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[prometheus] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[prometheus] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/prometheus] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/prometheus/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/prometheus/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/prometheus/run from none to 60f91b
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/prometheus/run	2020-01-03 12:38:39.675941416 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/prometheus/.chef-run20200103-12696-cvibhd	2020-01-03 12:38:39.675941416 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,9 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +umask 077
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -P -e /opt/gitlab/etc/prometheus/env \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -U gitlab-prometheus:gitlab-prometheus \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -u gitlab-prometheus:gitlab-prometheus \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /opt/gitlab/embedded/bin/prometheus --web.listen-address=localhost:9090 --storage.tsdb.path=/var/opt/gitlab/prometheus/data --config.file=/var/opt/gitlab/prometheus/prometheus.yml
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/prometheus/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/prometheus/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/prometheus/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/prometheus/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/prometheus/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/prometheus/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/prometheus/log/run from none to 072b20
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/prometheus/log/run	2020-01-03 12:38:39.687941416 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/prometheus/log/.chef-run20200103-12696-140tvji	2020-01-03 12:38:39.687941416 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/prometheus/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/prometheus/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/prometheus/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/prometheus/config	2020-01-03 12:38:39.715941419 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/prometheus/.chef-config20200103-12696-1h33141	2020-01-03 12:38:39.715941419 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_prometheus] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_prometheus] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/prometheus/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/prometheus/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for prometheus service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/prometheus/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/prometheus/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/prometheus/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/prometheus/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/prometheus] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/prometheus to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/prometheus/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/prometheus/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/prometheus/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/prometheus/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_prometheus] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for prometheus service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/prometheus/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/prometheus/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/prometheus] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/prometheus/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/prometheus] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/prometheus to /opt/gitlab/sv/prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for prometheus service socket] action run
module.gitlab.aws_instance.gitlab[0]: Still creating... [4m0s elapsed]

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for prometheus service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/prometheus/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/prometheus/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/prometheus/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_prometheus] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for prometheus service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/prometheus/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/prometheus/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/prometheus/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/prometheus] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/prometheus/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/prometheus] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for prometheus service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/prometheus] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for prometheus service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * consul_service[prometheus] action delete
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/var/opt/gitlab/consul/config.d/prometheus-service.json] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start prometheus] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: prometheus: (pid 13745) 1s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/prometheus/rules/gitlab.rules] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/prometheus/rules/gitlab.rules
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/prometheus/rules/gitlab.rules from none to 8f5b0b
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/prometheus/rules/gitlab.rules	2020-01-03 12:38:43.803941775 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/prometheus/rules/.chef-gitlab20200103-12696-1lekxjd.rules	2020-01-03 12:38:43.803941775 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,454 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +---
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +groups:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: GitLab
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  rules:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: instance:unicorn_utilization:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum by (instance) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        unicorn_active_connections
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ) /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      count by (instance) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        ruby_memory_bytes
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: job_grpc:grpc_server_handled_total:rate5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum by (job, grpc_code, grpc_method, grpc_service, grpc_type) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        rate(grpc_server_handled_total[5m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: job_route_method_code:gitlab_workhorse_http_request_duration_seconds_count:rate5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum by (job, route, method, code) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        rate(gitlab_workhorse_http_request_duration_seconds_count[5m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: ServiceDown
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: avg_over_time(up[5m]) * 100 < 50
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: The service {{ $labels.job }} instance {{ $labels.instance }} is
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        not responding for more than 50% of the time for 5 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: The service {{ $labels.job }} is not responding
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: RedisDown
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: avg_over_time(redis_up[5m]) * 100 < 50
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: The Redis service {{ $labels.job }} instance {{ $labels.instance
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        }} is not responding for more than 50% of the time for 5 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: The Redis service {{ $labels.job }} is not responding
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: PostgresDown
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: avg_over_time(pg_up[5m]) * 100 < 50
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: The Postgres service {{ $labels.job }} instance {{ $labels.instance
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        }} is not responding for more than 50% of the time for 5 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: The Postgres service {{ $labels.job }} is not responding
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: UnicornQueueing
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: avg_over_time(unicorn_queued_connections[30m]) > 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: Unicorn instance {{ $labels.instance }} is queueing requests with
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        an average of {{ $value | printf "%.1f" }} over the last 30 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: Unicorn is queueing requests
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: HighUnicornUtilization
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: instance:unicorn_utilization:ratio * 100 > 90
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    for: 60m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: Unicorn instance {{ $labels.instance }} has more than 90% worker utilization ({{ $value | printf "%.1f" }}%) over the last 60 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: Unicorn is has high utilization
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: SidekiqJobsQueuing
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: sum by (name) (sidekiq_queue_size) > 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    for: 60m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: Sidekiq has jobs queued
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: Sidekiq queue {{ $labels.name }} has {{ $value }} jobs queued for 60 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: HighgRPCResourceExhaustedRate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum without (grpc_code) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        job_grpc:grpc_server_handled_total:rate5m{grpc_code="ResourceExhausted"}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ) /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum without (grpc_code) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        job_grpc:grpc_server_handled_total:rate5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ) * 100 > 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    for: 60m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: High gRPC ResourceExhausted error rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: gRPC is returning more than 1% ({{ $value | printf "%.1f" }}%) ResourceExhausted errors over the last 60 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: PostgresDatabaseDeadlocks
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: increase(pg_stat_database_deadlocks[5m]) > 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: Postgres database has deadlocks
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: Postgres database {{ $labels.instance }} had {{ $value | printf "%d" }} deadlocks in the last 5 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: PostgresDatabaseDeadlockCancels
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: increase(pg_stat_database_deadlocks[5m]) > 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: Postgres database has queries canceled due to deadlocks
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: Postgres database {{ $labels.instance }} had {{ $value | printf "%d" }} queries canceled due to deadlocks in the last 5 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Low-traffic - < 10 QPS (600 RPM)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: WorkhorseHighErrorRate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum without (job, code) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          job_route_method_code:gitlab_workhorse_http_request_duration_seconds_count:rate5m{code=~"5.."}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        ) /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum without (job,code) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          job_route_method_code:gitlab_workhorse_http_request_duration_seconds_count:rate5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        ) < 10
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ) * 100 > 50
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: Workhorse has high error rates
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: Workhorse route {{ $labels.route }} method {{ $labels.method }} has more than 50% errors ({{ $value | printf "%.1f" }}%) for the last 60 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # High-traffic - >= 10 QPS (600 RPM)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: WorkhorseHighErrorRate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum without (job, code) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          job_route_method_code:gitlab_workhorse_http_request_duration_seconds_count:rate5m{code=~"5.."}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        ) /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum without (job,code) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          job_route_method_code:gitlab_workhorse_http_request_duration_seconds_count:rate5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        ) > 10
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ) * 100 > 10
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: Workhorse has high error rates
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: Workhorse route {{ $labels.route }} method {{ $labels.method }} has more than 10% errors ({{ $value | printf "%.1f" }}%) for the last 60 minutes.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +###
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# These metrics are top-level GitLab Service Level Indicators (SLIs). They can
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# be used to monitor the overall health of a GitLab instance.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: Service Level Indicators
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  interval: 30s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  rules:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Service availability.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:job:availability:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      avg by (job) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        avg_over_time(up[30s])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Rails worker/thread capacity.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:rails_active_connections:avg30s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(avg_over_time(unicorn_active_connections[30s])) or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(avg_over_time(puma_active_connections[30s]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:rails_queued_connections:avg30s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(avg_over_time(unicorn_queued_connections[30s])) or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(avg_over_time(puma_queued_connections[30s]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:rails_active_connections:max30s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(max_over_time(unicorn_active_connections[30s])) or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(max_over_time(puma_active_connections[30s]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:rails_queued_connections:max30s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(max_over_time(unicorn_queued_connections[30s])) or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(max_over_time(puma_queued_connections[30s]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:rails_workers:avg30s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      count(avg_over_time(ruby_memory_bytes[30s])) or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(avg_over_time(puma_max_threads[30s]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Redis CPU use.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:redis_cpu_seconds:rate1m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      (sum(rate(redis_used_cpu_sys[1m])) + sum(rate(redis_used_cpu_user[1m]))) or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      (sum(rate(redis_cpu_sys_seconds_total[1m])) + sum(rate(redis_cpu_user_seconds_total[1m])))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Workhorse traffic.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:code_method_route:workhorse_http_request_count:rate1m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum by (code,method,route) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        rate(gitlab_workhorse_http_request_duration_seconds_count[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:code_method_route:workhorse_http_request_duration_seconds:rate1m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum by (code,method,route) (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        rate(gitlab_workhorse_http_request_duration_seconds_sum[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# SLI - Apdex
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: Service Level Indicators - Apdex
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  interval: 1m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  rules:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Gitaly goserver
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Satisfied -> 0.5 seconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Acceptable -> 1 seconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_apdex:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      job: gitaly
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum(rate(grpc_server_handling_seconds_bucket{job="gitaly",grpc_type="unary",le="0.5",grpc_method!~"GarbageCollect|Fsck|RepackFull|RepackIncremental|CommitLanguages|CreateRepositoryFromURL|UserRebase|UserSquash|CreateFork|UserUpdateBranch|FindRemoteRepository|UserCherryPick|FetchRemote|UserRevert|FindRemoteRootRef"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum(rate(grpc_server_handling_seconds_bucket{job="gitaly",grpc_type="unary",le="1",grpc_method!~"GarbageCollect|Fsck|RepackFull|RepackIncremental|CommitLanguages|CreateRepositoryFromURL|UserRebase|UserSquash|CreateFork|UserUpdateBranch|FindRemoteRepository|UserCherryPick|FetchRemote|UserRevert|FindRemoteRootRef"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      2 / sum(rate(grpc_server_handling_seconds_count{job="gitaly",grpc_type="unary",grpc_method!~"GarbageCollect|Fsck|RepackFull|RepackIncremental|CommitLanguages|CreateRepositoryFromURL|UserRebase|UserSquash|CreateFork|UserUpdateBranch|FindRemoteRepository|UserCherryPick|FetchRemote|UserRevert|FindRemoteRootRef"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Sidekiq TODO: https://gitlab.com/gitlab-org/gitlab-foss/issues/56752
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # - record: gitlab_sli:gitlab_component_apdex:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #   labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     job: gitlab-sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #   expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #       sum(rate(sidekiq_jobs_completion_time_seconds_bucket{le="25"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #       sum(rate(sidekiq_jobs_completion_time_seconds_bucket{le="50"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     / 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     sum(rate(sidekiq_jobs_completion_time_seconds_count[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Satisfied -> 1 seconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Acceptable -> 10 seconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_apdex:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      job: gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum(rate(gitlab_workhorse_http_request_duration_seconds_bucket{le="1",route!="^/([^/]+/){1,}[^/]+/uploads\\z",route!="^/api/v4/jobs/request\\z"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum(rate(gitlab_workhorse_http_request_duration_seconds_bucket{le="10",route!="^/([^/]+/){1,}[^/]+/uploads\\z",route!="^/api/v4/jobs/request\\z"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      2 / sum(rate(gitlab_workhorse_http_request_duration_seconds_count{route!="^/([^/]+/){1,}[^/]+/uploads\\z",route!="^/api/v4/jobs/request\\z"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# SLI - Errors
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: Service Level Indicators - Errors
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  interval: 1m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  rules:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # PostgreSQL
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_ops:rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      job: postgres
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(rate(pg_stat_database_xact_commit[1m])) +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(rate(pg_stat_database_xact_rollback[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_errors:rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      job: postgres
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: sum(rate(pg_stat_database_xact_rollback[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Rails (Unicorn/Puma)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_ops:rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      job: gitlab-rails
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        rate(http_request_duration_seconds_count{job="gitlab-rails"}[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_errors:rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      job: gitlab-rails
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        rate(http_request_duration_seconds_count{job="gitlab-rails",status=~"5.."}[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Sidekiq TODO: https://gitlab.com/gitlab-org/gitlab-foss/issues/56752
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # - record: gitlab_sli:gitlab_component_ops:rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #   labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     job: gitlab-sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #   expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     sum (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #       rate(sidekiq_jobs_started_total{job="gitlab-sidekiq"}[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # - record: gitlab_sli:gitlab_component_errors:rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #   labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     job: gitlab-sidekiq
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #   expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     sum (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #       rate(sidekiq_jobs_failed_total{job="gitlab-sidekiq"}[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  #     )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_ops:rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      job: gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        rate(gitlab_workhorse_http_requests_total{job="gitlab-workhorse"}[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_errors:rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      job: gitlab-workhorse
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      sum(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        rate(gitlab_workhorse_http_requests_total{job="gitlab-workhorse",code=~"5.."}[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  ###
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Calculate service error ratios
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_errors:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      gitlab_sli:gitlab_component_errors:rate /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      gitlab_sli:gitlab_component_ops:rate
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: GitLab Saturation Ratios
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  interval: 1m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  rules:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # type: *, component: cpu
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # this measures average CPU across all the cores for the entire fleet for the given service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'cpu'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      avg(1 - rate(node_cpu_seconds_total{mode="idle"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # type: *, component: single_node_cpu
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # this measures the maximum cpu availability across all the codes on a single server
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # this can be helpful if CPU is not even distributed across the fleet.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'single_node_cpu'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        avg(1 - rate(node_cpu_seconds_total{mode="idle"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'disk_space'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +            node_filesystem_size_bytes{fstype=~"ext.|xfs|nfs.?"}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +            -
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +            node_filesystem_free_bytes{fstype=~"ext.|xfs|nfs.?"}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          node_filesystem_size_bytes{fstype=~"ext.|xfs|nfs.?"}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'memory'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      max (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +       1 -
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +       (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +         node_memory_MemAvailable_bytes or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +         (node_memory_MemFree_bytes + node_memory_Buffers_bytes + node_memory_Cached_bytes)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +       ) /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +       node_memory_MemTotal_bytes
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'unicorn'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      clamp_max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum(avg_over_time(unicorn_active_connections{job=~"gitlab-(rails|unicorn)"}[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        sum(max(unicorn_workers) without (pid)),
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'single_threaded_cpu'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      clamp_max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        max (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +         (rate(redis_cpu_user_seconds_total[1m]) + rate(redis_cpu_sys_seconds_total[1m])) or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +         (rate(redis_used_cpu_user[1m]) + rate(redis_used_cpu_sys[1m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        ),
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'connection_pool'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      clamp_max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          max_over_time(pgbouncer_pools_server_active_connections{user="gitlab"}[1m]) /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +            (
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +              pgbouncer_pools_server_idle_connections{user="gitlab"} +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +              pgbouncer_pools_server_active_connections{user="gitlab"} +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +              pgbouncer_pools_server_testing_connections{user="gitlab"} +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +              pgbouncer_pools_server_used_connections{user="gitlab"} +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +              pgbouncer_pools_server_login_connections{user="gitlab"}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +            )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +            > 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ), 1)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # type: postgres-delayed, postgres-archive, patroni
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'active_db_connections'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      clamp_max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          sum without(state) (pg_stat_activity_count{datname="gitlabhq_production", state!="idle"})
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +          (sum without(state) (pg_stat_activity_count{datname="gitlabhq_production"}) > 0)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      ), 1)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # type: redis, redis-cache, component: redis_clients
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Records the saturation of redis client connections against a redis fleet
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'redis_clients'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        max_over_time(redis_connected_clients[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        redis_config_maxclients
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Aggregate over all components within a service using max
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_service_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      max by (component) (gitlab_sli:gitlab_component_saturation:ratio)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Calculate the "sapdex" - the saturation apdex for the metric. 1 < less then soft limit, 0.5 < hard limit, else 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio:sapdex
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      clamp_min(gitlab_sli:gitlab_component_saturation:ratio <= on(component) group_left slo:max:soft:gitlab_sli:gitlab_component_saturation:ratio, 1)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      clamp_min(clamp_max(gitlab_sli:gitlab_component_saturation:ratio > on(component) group_left slo:max:soft:gitlab_sli:gitlab_component_saturation:ratio, 0.5), 0.5)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      or
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      clamp_max(gitlab_sli:gitlab_component_saturation:ratio > on(component) group_left slo:max:hard:gitlab_sli:gitlab_component_saturation:ratio, 0)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Open file descriptors
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'open_fds'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        max_over_time(process_open_fds[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        max_over_time(process_max_fds[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    labels:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      component: 'open_fds'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      max(
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        max_over_time(ruby_file_descriptors[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        /
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        max_over_time(ruby_process_max_fds[1m])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      )
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Unlike other service metrics, we record the stats for each component independently
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: GitLab Saturation Ratios Stats
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  interval: 5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  rules:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Average values for each service, over a week
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio:avg_over_time_1w
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      avg_over_time(gitlab_sli:gitlab_component_saturation:ratio[1w])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Using linear week-on-week growth, what prediction to we have for 2w from now?
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio:predict_linear_2w
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      predict_linear(gitlab_sli:gitlab_component_saturation:ratio:avg_over_time_1w[1w], 86400 * 14)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Using linear week-on-week growth, what prediction to we have for 30d from now?
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio:predict_linear_30d
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      predict_linear(gitlab_sli:gitlab_component_saturation:ratio:avg_over_time_1w[1w], 86400 * 30)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Sapdex, average for week
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio:sapdex:avg_over_time_1w
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      avg_over_time(gitlab_sli:gitlab_component_saturation:ratio:sapdex[1w])
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Sapdex long term trend forecasting
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  # Using linear week-on-week growth, what prediction to we have for 30d from now?
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: gitlab_sli:gitlab_component_saturation:ratio:sapdex:avg_over_time_1w:predict_linear_30d
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: >
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      predict_linear(gitlab_sli:gitlab_component_saturation:ratio:sapdex:avg_over_time_1w[1w], 86400 * 30)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/prometheus/rules/node.rules] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/prometheus/rules/node.rules
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/prometheus/rules/node.rules from none to 9e885c
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/prometheus/rules/node.rules	2020-01-03 12:38:43.859941780 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/prometheus/rules/.chef-node20200103-12696-1jfn0zv.rules	2020-01-03 12:38:43.859941780 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,37 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +groups:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: Node
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  rules:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: instance:node_cpus:count
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: count without(cpu, mode) (node_cpu{mode="idle"})
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: instance:node_cpus:count
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: count without(cpu, mode) (node_cpu_seconds_total{mode="idle"})
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: instance_cpu:node_cpu_seconds_not_idle:rate5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: sum without(mode) (rate(node_cpu{mode!="idle"}[5m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: instance_cpu:node_cpu_seconds_not_idle:rate5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: sum without(mode) (rate(node_cpu_seconds_total{mode!="idle"}[5m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: instance_mode:node_cpu_seconds:rate5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: sum without(cpu) (rate(node_cpu[5m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: instance_mode:node_cpu_seconds:rate5m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: sum without(cpu) (rate(node_cpu_seconds_total[5m]))
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: instance:node_cpu_utilization:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: sum without(mode) (instance_mode:node_cpu_seconds:rate5m{mode!="idle"})
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      / instance:node_cpus:count
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - record: instance:node_filesystem_avail:ratio
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: node_filesystem_avail_bytes / (node_filesystem_size_bytes > 0)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: FilesystemAlmostFull
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: instance:node_filesystem_avail:ratio * 100 < 5
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    for: 10m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: The filesystem {{ $labels.device }}:{{ $labels.mountpoint }} on
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        {{ $labels.instance }} has {{ $value | printf "%.2f" }}% space available.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: The filesystem {{ $labels.device }}:{{ $labels.mountpoint }} is almost
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        full
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  - alert: FilesystemFullIn1Day
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    expr: predict_linear(node_filesystem_avail_bytes[6h], 24 * 3600) < 0
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    for: 30m
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    annotations:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      description: The filesystem {{ $labels.device }}:{{ $labels.mountpoint }} on
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        {{ $labels.instance }} will be full in the next 24 hours.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      summary: The filesystem {{ $labels.device }}:{{ $labels.mountpoint }} will be
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        full within 24 hours
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::alertmanager
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/alertmanager] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/alertmanager
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0750'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/alertmanager] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/alertmanager
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/opt/gitlab/etc/alertmanager/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /opt/gitlab/etc/alertmanager/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * env_dir[/opt/gitlab/etc/alertmanager/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/etc/alertmanager/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/alertmanager/env/SSL_CERT_DIR] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/alertmanager/env/SSL_CERT_DIR
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/alertmanager/env/SSL_CERT_DIR from none to 4f45cf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/alertmanager/env/SSL_CERT_DIR	2020-01-03 12:38:43.899941783 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/alertmanager/env/.chef-SSL_CERT_DIR20200103-12696-9chkc4	2020-01-03 12:38:43.899941783 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/opt/gitlab/embedded/ssl/certs/
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[Alertmanager config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/alertmanager/alertmanager.yml
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/alertmanager/alertmanager.yml from none to 21b7be
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/alertmanager/alertmanager.yml	2020-01-03 12:38:43.903941784 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/alertmanager/.chef-alertmanager20200103-12696-1bve7vb.yml	2020-01-03 12:38:43.903941784 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,10 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +---
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +global: {}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +templates: []
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +route:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  receiver: default-receiver
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  routes: []
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +receivers:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: default-receiver
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +inhibit_rules: []
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[alertmanager] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::alertmanager
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[alertmanager] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/alertmanager] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/alertmanager
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/alertmanager/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/alertmanager/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/alertmanager/run from none to 36da8b
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/alertmanager/run	2020-01-03 12:38:43.931941786 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/alertmanager/.chef-run20200103-12696-1whb1ku	2020-01-03 12:38:43.931941786 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,9 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +umask 077
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -P -e /opt/gitlab/etc/alertmanager/env \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -U gitlab-prometheus:gitlab-prometheus \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -u gitlab-prometheus:gitlab-prometheus \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /opt/gitlab/embedded/bin/alertmanager --web.listen-address=localhost:9093 --storage.path=/var/opt/gitlab/alertmanager/data --config.file=/var/opt/gitlab/alertmanager/alertmanager.yml
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/alertmanager/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/alertmanager/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/alertmanager/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/alertmanager/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/alertmanager/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/alertmanager/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/alertmanager/log/run from none to 2feab9
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/alertmanager/log/run	2020-01-03 12:38:43.947941788 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/alertmanager/log/.chef-run20200103-12696-1drkqqi	2020-01-03 12:38:43.947941788 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/alertmanager
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/alertmanager/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/alertmanager/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/alertmanager/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/alertmanager/config	2020-01-03 12:38:43.955941788 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/alertmanager/.chef-config20200103-12696-nk222n	2020-01-03 12:38:43.955941788 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_alertmanager] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_alertmanager
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_alertmanager] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/alertmanager/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/alertmanager/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for alertmanager service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/alertmanager/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/alertmanager/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/alertmanager/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/alertmanager/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/alertmanager] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/alertmanager to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/alertmanager/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/alertmanager/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/alertmanager/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/alertmanager/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_alertmanager] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for alertmanager service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/alertmanager/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/alertmanager/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/alertmanager] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/alertmanager/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/alertmanager] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/alertmanager to /opt/gitlab/sv/alertmanager
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for alertmanager service socket] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for alertmanager service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/alertmanager/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/alertmanager/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/alertmanager/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_alertmanager] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for alertmanager service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/alertmanager/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/alertmanager/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/alertmanager/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/alertmanager] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/alertmanager/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/alertmanager] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for alertmanager service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/alertmanager] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for alertmanager service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start alertmanager] action run
module.gitlab.aws_instance.gitlab[0]: Still creating... [4m10s elapsed]

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: alertmanager: (pid 13793) 4s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start alertmanager
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::postgres-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/postgres-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/postgres-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/postgres-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/postgres-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * env_dir[/opt/gitlab/etc/postgres-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/etc/postgres-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/etc/postgres-exporter/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/postgres-exporter/env/SSL_CERT_DIR] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/postgres-exporter/env/SSL_CERT_DIR
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/postgres-exporter/env/SSL_CERT_DIR from none to 4f45cf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/postgres-exporter/env/SSL_CERT_DIR	2020-01-03 12:38:52.211942434 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/postgres-exporter/env/.chef-SSL_CERT_DIR20200103-12696-10tpp12	2020-01-03 12:38:52.211942434 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/opt/gitlab/embedded/ssl/certs/
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/postgres-exporter/env/DATA_SOURCE_NAME] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/postgres-exporter/env/DATA_SOURCE_NAME
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/postgres-exporter/env/DATA_SOURCE_NAME from none to 1949e6
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/postgres-exporter/env/DATA_SOURCE_NAME	2020-01-03 12:38:52.215942435 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/postgres-exporter/env/.chef-DATA_SOURCE_NAME20200103-12696-w1muob	2020-01-03 12:38:52.215942435 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +user=gitlab-psql host=/var/opt/gitlab/postgresql database=postgres
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[postgres-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::postgres-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[postgres-exporter] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgres-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgres-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/postgres-exporter/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/postgres-exporter/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/postgres-exporter/run from none to b40d34
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/postgres-exporter/run	2020-01-03 12:38:52.227942436 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/postgres-exporter/.chef-run20200103-12696-1i8bc3g	2020-01-03 12:38:52.227942436 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +umask 077
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -e /opt/gitlab/etc/postgres-exporter/env -P -U gitlab-psql:git -u gitlab-psql:git /opt/gitlab/embedded/bin/postgres_exporter --web.listen-address=localhost:9187 --extend.query-path=/var/opt/gitlab/postgres-exporter/queries.yaml
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgres-exporter/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgres-exporter/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgres-exporter/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgres-exporter/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/postgres-exporter/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/postgres-exporter/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/postgres-exporter/log/run from none to b971c9
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/postgres-exporter/log/run	2020-01-03 12:38:52.235942436 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/postgres-exporter/log/.chef-run20200103-12696-148z4cy	2020-01-03 12:38:52.235942436 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/postgres-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/postgres-exporter/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/postgres-exporter/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/postgres-exporter/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/postgres-exporter/config	2020-01-03 12:38:52.235942436 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/postgres-exporter/.chef-config20200103-12696-17k0cwv	2020-01-03 12:38:52.235942436 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_postgres-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_postgres-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_postgres-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgres-exporter/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgres-exporter/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for postgres-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/postgres-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/postgres-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/postgres-exporter/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/postgres-exporter/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/postgres-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/postgres-exporter to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/postgres-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgres-exporter/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgres-exporter/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/postgres-exporter/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_postgres-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for postgres-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgres-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgres-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/postgres-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgres-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/postgres-exporter] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/postgres-exporter to /opt/gitlab/sv/postgres-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for postgres-exporter service socket] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for postgres-exporter service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgres-exporter/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgres-exporter/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/postgres-exporter/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_postgres-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for postgres-exporter service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgres-exporter/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/postgres-exporter/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/postgres-exporter/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/postgres-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/postgres-exporter/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/postgres-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for postgres-exporter service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/postgres-exporter] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for postgres-exporter service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/postgres-exporter/queries.yaml] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/postgres-exporter/queries.yaml
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/postgres-exporter/queries.yaml from none to 40142b
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/postgres-exporter/queries.yaml	2020-01-03 12:38:56.603942745 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/postgres-exporter/.chef-queries20200103-12696-1kob2o.yaml	2020-01-03 12:38:56.603942745 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,175 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pg_replication:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  query: "SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::INT as lag, CASE WHEN pg_is_in_recovery() THEN 1 ELSE 0 END as is_replica"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - lag:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Replication lag behind master in seconds"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - is_replica:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Indicates if this host is a slave"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pg_postmaster:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  query: "SELECT pg_postmaster_start_time as start_time_seconds from pg_postmaster_start_time()"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - start_time_seconds:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Time at which postmaster started"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pg_stat_user_tables:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  query: "SELECT schemaname, relname, seq_scan, seq_tup_read, idx_scan, idx_tup_fetch, n_tup_ins, n_tup_upd, n_tup_del, n_tup_hot_upd, n_live_tup, n_dead_tup, n_mod_since_analyze, last_vacuum, last_autovacuum, last_analyze, last_autoanalyze, vacuum_count, autovacuum_count, analyze_count, autoanalyze_count FROM pg_stat_user_tables"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - schemaname:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "LABEL"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Name of the schema that this table is in"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - relname:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "LABEL"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Name of this table"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - seq_scan:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of sequential scans initiated on this table"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - seq_tup_read:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of live rows fetched by sequential scans"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - idx_scan:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of index scans initiated on this table"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - idx_tup_fetch:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of live rows fetched by index scans"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - n_tup_ins:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of rows inserted"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - n_tup_upd:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of rows updated"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - n_tup_del:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of rows deleted"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - n_tup_hot_upd:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of rows HOT updated (i.e., with no separate index update required)"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - n_live_tup:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Estimated number of live rows"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - n_dead_tup:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Estimated number of dead rows"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - n_mod_since_analyze:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Estimated number of rows changed since last analyze"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - last_vacuum:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Last time at which this table was manually vacuumed (not counting VACUUM FULL)"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - last_autovacuum:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Last time at which this table was vacuumed by the autovacuum daemon"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - last_analyze:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Last time at which this table was manually analyzed"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - last_autoanalyze:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Last time at which this table was analyzed by the autovacuum daemon"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - vacuum_count:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of times this table has been manually vacuumed (not counting VACUUM FULL)"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - autovacuum_count:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of times this table has been vacuumed by the autovacuum daemon"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - analyze_count:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of times this table has been manually analyzed"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - autoanalyze_count:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "COUNTER"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Number of times this table has been analyzed by the autovacuum daemon"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pg_total_relation_size:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  query: |
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    SELECT relnamespace::regnamespace as schemaname,
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +           relname as relname,
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +           pg_total_relation_size(oid) bytes
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      FROM pg_class
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +     WHERE relkind = 'r';
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - schemaname:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "LABEL"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Name of the schema that this table is in"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - relname:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "LABEL"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Name of this table"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - bytes:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "total disk space usage for the specified table and associated indexes"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pg_blocked:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  query: |
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    SELECT
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      count(blocked.transactionid) AS queries,
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      '__transaction__' AS table
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    FROM pg_catalog.pg_locks blocked
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    WHERE NOT blocked.granted AND locktype = 'transactionid'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    GROUP BY locktype
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    UNION
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    SELECT
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      count(blocked.relation) AS queries,
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      blocked.relation::regclass::text AS table
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    FROM pg_catalog.pg_locks blocked
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    WHERE NOT blocked.granted AND locktype != 'transactionid'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    GROUP BY relation
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - queries:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "The current number of blocked queries"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - table:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "LABEL"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "The table on which a query is blocked"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pg_slow:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  query: |
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    SELECT COUNT(*) AS queries
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    FROM pg_stat_activity
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    WHERE state = 'active' AND (now() - query_start) > '1 seconds'::interval
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - queries:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Current number of slow queries"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pg_vacuum:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  query: |
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    SELECT
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      COUNT(*) AS queries,
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      MAX(EXTRACT(EPOCH FROM (clock_timestamp() - query_start))) AS age_in_seconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    FROM pg_catalog.pg_stat_activity
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    WHERE state = 'active' AND trim(query) ~* '\AVACUUM (?!ANALYZE)'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - queries:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "The current number of VACUUM queries"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - age_in_seconds:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "The current maximum VACUUM query age in seconds"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pg_vacuum_analyze:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  query: |
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    SELECT
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      COUNT(*) AS queries,
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +      MAX(EXTRACT(EPOCH FROM (clock_timestamp() - query_start))) AS age_in_seconds
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    FROM pg_catalog.pg_stat_activity
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    WHERE state = 'active' AND trim(query) ~* '\AVACUUM ANALYZE'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - queries:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "The current number of VACUUM ANALYZE queries"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - age_in_seconds:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "The current maximum VACUUM ANALYZE query age in seconds"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +pg_stuck_idle_in_transaction:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  query: |
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    SELECT COUNT(*) AS queries
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    FROM pg_stat_activity
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    WHERE state = 'idle in transaction' AND (now() - query_start) > '10 minutes'::interval
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  metrics:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    - queries:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        usage: "GAUGE"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +        description: "Current number of queries that are stuck being idle in transactions"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-psql'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start postgres-exporter] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: postgres-exporter: (pid 13863) 3s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start postgres-exporter
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * consul_service[postgres-exporter] action delete
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/var/opt/gitlab/consul/config.d/postgres-exporter-service.json] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/log/gitlab/grafana] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/log/gitlab/grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/grafana] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/grafana/provisioning] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/grafana/provisioning
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/grafana/provisioning/dashboards] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/grafana/provisioning/dashboards
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/grafana/provisioning/datasources] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/grafana/provisioning/datasources
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/grafana/provisioning/notifiers] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /var/opt/gitlab/grafana/provisioning/notifiers
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[/var/opt/gitlab/grafana/CVE_reset_status] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/grafana/CVE_reset_status
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/grafana/CVE_reset_status from none to 5feceb
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/grafana/CVE_reset_status2020-01-03 12:38:57.135942781 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/grafana/.chef-CVE_reset_status20200103-12696-70fxyt	2020-01-03 12:38:57.135942781 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +0
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * link[/var/opt/gitlab/grafana/conf] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create symlink at /var/opt/gitlab/grafana/conf to /opt/gitlab/embedded/service/grafana/conf
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * link[/var/opt/gitlab/grafana/public] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create symlink at /var/opt/gitlab/grafana/public to /opt/gitlab/embedded/service/grafana/public
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/opt/gitlab/etc/grafana/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new directory /opt/gitlab/etc/grafana/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0700'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * ruby_block[authorize Grafana with GitLab] action run
module.gitlab.aws_instance.gitlab[0]: Still creating... [4m20s elapsed]
module.gitlab.aws_instance.gitlab[
  module.gitlab.aws_instance.gitlab[0]: Still creating... [4m30s elapsed]
module.gitlab.aws_instance.gitlab[0]: Still creating... [4m40s elapsed]

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute the ruby block authorize Grafana with GitLab
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * ruby_block[populate Grafana configuration options] action run
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute the ruby block populate Grafana configuration options
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * env_dir[/opt/gitlab/etc/grafana/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/etc/grafana/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/etc/grafana/env/SSL_CERT_DIR] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/etc/grafana/env/SSL_CERT_DIR
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/etc/grafana/env/SSL_CERT_DIR from none to 4f45cf
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/etc/grafana/env/SSL_CERT_DIR	2020-01-03 12:39:25.467944410 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/etc/grafana/env/.chef-SSL_CERT_DIR20200103-12696-1sefqwo	2020-01-03 12:39:25.467944410 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,2 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +/opt/gitlab/embedded/ssl/certs/
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * template[/var/opt/gitlab/grafana/grafana.ini] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/grafana/grafana.ini
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/grafana/grafana.ini from none to 043eb0
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/grafana/grafana.ini	2020-01-03 12:39:25.471944409 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/grafana/.chef-grafana20200103-12696-mqm1j7.ini	2020-01-03 12:39:25.471944409 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,401 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +##################### GitLab Grafana Configuration #####################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Everything has defaults so you only need to uncomment things you want to
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# change
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# possible values : production, development
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;app_mode = production
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# instance name, defaults to HOSTNAME environment variable value or hostname if HOSTNAME var is empty
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;instance_name = ${HOSTNAME}
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Paths ####################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[paths]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +data = /var/opt/gitlab/grafana/data
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Temporary files in `data` directory older than given duration will be removed
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;temp_data_lifetime = 24h
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Directory where grafana can store logs
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +logs = /var/log/gitlab/grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Directory where grafana will automatically scan and look for plugins
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;plugins = /var/lib/grafana/plugins
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# folder that contains provisioning config files that grafana will apply on startup and while running.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +provisioning = provisioning
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Server ####################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[server]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Protocol (http, https, socket)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +protocol = http
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# The ip address to bind to, empty will bind to all interfaces
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +http_addr = localhost
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# The http port  to use
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +http_port = 3000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# The public facing domain name used to access grafana from a browser
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;domain = localhost
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Redirect to correct domain if host header does not match domain
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Prevents DNS rebinding attacks
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +enforce_domain = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# The full public facing url you use in browser, used for redirects and emails
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# If you use reverse proxy and sub path specify full url (with sub path)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +root_url = http://tfe-ssc-3-gitlab.guselietov.com/-/grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Log web requests
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;router_logging = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# the path relative working path
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;static_root_path = public
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# enable gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;enable_gzip = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# https certs & key file
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;cert_file =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;cert_key =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Unix socket path
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;socket =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Database ####################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[database]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# You can configure the database connection by specifying type, host, name, user and password
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# as separate properties or as on string using the url properties.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Either "mysql", "postgres" or "sqlite3", it's your choice
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;type = sqlite3
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;host = 127.0.0.1:3306
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;name = grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;user = root
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# If the password contains # or ; you have to wrap it with triple quotes. Ex """#password;"""
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;password =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Use either URL or the previous fields to configure the database
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Example: mysql://user:secret@host:port/database
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;url =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# For "postgres" only, either "disable", "require" or "verify-full"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;ssl_mode = disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# For "sqlite3" only, path relative to data_path setting
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;path = grafana.db
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Max idle conn setting default is 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;max_idle_conn = 2
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Max conn setting default is 0 (mean not set)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;max_open_conn =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Connection Max Lifetime default is 14400 (means 14400 seconds or 4 hours)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;conn_max_lifetime = 14400
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Set to true to log the sql calls and execution times.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +log_queries =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Session ####################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[session]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Either "memory", "file", "redis", "mysql", "postgres", default is "file"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;provider = file
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Provider config options
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# memory: not have any config yet
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# file: session dir path, is relative to grafana data_path
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# redis: config like redis server e.g. `addr=127.0.0.1:6379,pool_size=100,db=grafana`
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# mysql: go-sql-driver/mysql dsn config string, e.g. `user:password@tcp(127.0.0.1:3306)/database_name`
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# postgres: user=a password=b host=localhost port=5432 dbname=c sslmode=disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;provider_config = sessions
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Session cookie name
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;cookie_name = grafana_sess
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# If you use session in https only, default is false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;cookie_secure = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Session life time, default is 86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;session_life_time = 86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Data proxy ###########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[dataproxy]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# This enables data proxy logging, default is false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;logging = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Analytics ####################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[analytics]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Server reporting, sends usage counters to stats.grafana.org every 24 hours.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# No ip addresses are being tracked, only simple counters to track
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# running instances, dashboard and error counts. It is very helpful to us.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Change this option to false to disable reporting.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;reporting_enabled = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Set to false to disable all checks to https://grafana.net
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# for new vesions (grafana itself and plugins), check is used
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# in some UI views to notify that grafana or plugin update exists
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# This option does not cause any auto updates, nor send any information
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# only a GET request to http://grafana.com to get latest versions
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;check_for_updates = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Google Analytics universal tracking code, only enabled if you specify an id here
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;google_analytics_ua_id =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Security ####################################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[security]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# default admin user, created on startup
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;admin_user = admin
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# default admin password, can be changed before first start of grafana,  or in profile settings
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +admin_password = 1d02034832dcd4ab8ed973abd1591fcb
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# used for signing
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +secret_key = c373e8dae66e26e92eefa549331b5f8b
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Auto-login remember days
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;login_remember_days = 7
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;cookie_username = grafana_user
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;cookie_remember_name = grafana_remember
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# disable gravatar profile images
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;disable_gravatar = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# data source proxy whitelist (ip_or_domain:port separated by spaces)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;data_source_proxy_whitelist =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# disable protection against brute force login attempts
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;disable_brute_force_login_protection = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Snapshots ###########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[snapshots]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# snapshot sharing options
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;external_enabled = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;external_snapshot_url = https://snapshots-origin.raintank.io
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;external_snapshot_name = Publish to snapshot.raintank.io
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# remove expired snapshot
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;snapshot_remove_expired = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Dashboards History ##################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[dashboards]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Number dashboard versions to keep (per dashboard). Default: 20, Minimum: 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;versions_to_keep = 20
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Users ###############################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[users]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# disable user signup / registration
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +allow_sign_up = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Allow non admin users to create organizations
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;allow_org_create = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Set to true to automatically assign new users to the default organization (id 1)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;auto_assign_org = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Default role new users will be automatically assigned (if disabled above is set to true)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;auto_assign_org_role = Viewer
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Background text for the user field on the login page
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;login_hint = email or username
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Default UI theme ("dark" or "light")
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;default_theme = dark
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# External user management, these options affect the organization users view
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;external_manage_link_url =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;external_manage_link_name =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;external_manage_info =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Viewers can edit/inspect dashboard settings in the browser. But not save the dashboard.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;viewers_can_edit = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[auth]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Set to true to disable (hide) the login form, useful if you use OAuth, defaults to false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;disable_login_form = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Set to true to disable the signout link in the side menu. useful if you use auth.proxy, defaults to false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;disable_signout_menu = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# URL to redirect the user to after sign out
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;signout_redirect_url =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Set to true to attempt login with OAuth automatically, skipping the login screen.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# This setting is ignored if multiple OAuth providers are configured.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;oauth_auto_login = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Anonymous Auth ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[auth.anonymous]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# enable anonymous access
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;enabled = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# specify organization name that should be used for unauthenticated users
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;org_name = Main Org.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# specify role for unauthenticated users
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;org_role = Viewer
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### GitLab Auth ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[auth.gitlab]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +enabled = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +allow_sign_up = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +client_id = 0466d909a529c6e21308fd112f55109486ae686ca7343b2fa2ef7b86aa7986ce
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +client_secret = ad62e2f254d7789050f7d092de1edfc5f0b026d998e35e245bad9f8967751941
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +scopes = api
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +auth_url = http://tfe-ssc-3-gitlab.guselietov.com/oauth/authorize
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +token_url = http://tfe-ssc-3-gitlab.guselietov.com/oauth/token
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +api_url = http://tfe-ssc-3-gitlab.guselietov.com/api/v4
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +allowed_groups =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Auth Proxy ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[auth.proxy]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;enabled = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;header_name = X-WEBAUTH-USER
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;header_property = username
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;auto_sign_up = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;ldap_sync_ttl = 60
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;whitelist = 192.168.1.1, 192.168.2.1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;headers = Email:X-User-Email, Name:X-User-Name
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Basic Auth ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[auth.basic]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +enabled = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +disable_login_form = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Auth LDAP ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[auth.ldap]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;enabled = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;config_file = /etc/grafana/ldap.toml
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;allow_sign_up = true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### SMTP / Emailing ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[smtp]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;enabled = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;host = localhost:25
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;user =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# If the password contains # or ; you have to wrap it with trippel quotes. Ex """#password;"""
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;password =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;cert_file =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;key_file =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;skip_verify = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;from_address = admin@grafana.localhost
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;from_name = Grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# EHLO identity in SMTP dialog (defaults to instance_name)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;ehlo_identity = dashboard.example.com
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[emails]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;welcome_email_on_sign_up = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Logging ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[log]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Either "console", "file", "syslog". Default is console and  file
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Use space to separate multiple modes, e.g. "console file"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +mode = console
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Either "debug", "info", "warn", "error", "critical", default is "info"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;level = info
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# optional settings to set different levels for specific loggers. Ex filters = sqlstore:debug
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;filters =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# For "console" mode only
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[log.console]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +level = info
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# log line format, valid options are text, console and json
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +format = text
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Alerting ############################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[alerting]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Disable alerting engine & UI features
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +enabled = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Explore #############################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[explore]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Enable the Explore section
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;enabled = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Internal Grafana Metrics ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Metrics available at HTTP API Url /metrics
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[metrics]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Disable / Enable internal metrics
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +enabled = false
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Publish interval
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;interval_seconds  = 10
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Send internal metrics to Graphite
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[metrics.graphite]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Enable by setting the address setting (ex localhost:2003)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;address =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;prefix = prod.grafana.%(instance_name)s.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Distributed tracing ############
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[tracing.jaeger]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Enable by setting the address sending traces to jaeger (ex localhost:6831)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;address = localhost:6831
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Tag that will always be included in when creating new spans. ex (tag1:value1,tag2:value2)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;always_included_tag = tag1:value1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Type specifies the type of the sampler: const, probabilistic, rateLimiting, or remote
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;sampler_type = const
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# jaeger samplerconfig param
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# for "const" sampler, 0 or 1 for always false/true respectively
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# for "probabilistic" sampler, a probability between 0 and 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# for "rateLimiting" sampler, the number of spans per second
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# for "remote" sampler, param is the same as for "probabilistic"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# and indicates the initial sampling rate before the actual one
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# is received from the mothership
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;sampler_param = 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### Grafana.com integration  ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Url used to import dashboards directly from Grafana.com
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[grafana_com]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;url = https://grafana.com
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +#################################### External image storage ##########################
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[external_image_storage]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Used for uploading images to public servers so they can be included in slack/email messages.
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# you can choose between (s3, webdav, gcs, azure_blob, local)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;provider =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[external_image_storage.s3]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;bucket =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;region =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;path =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;access_key =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;secret_key =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[external_image_storage.webdav]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;url =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;public_url =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;username =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;password =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[external_image_storage.gcs]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;key_file =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;bucket =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;path =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[external_image_storage.azure_blob]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;account_name =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;account_key =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;container_name =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[external_image_storage.local]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# does not require any configuration
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[rendering]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Options to configure external image rendering server like https://github.com/grafana/grafana-image-renderer
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;server_url =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;callback_url =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +[enterprise]
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +# Path to a valid Grafana Enterprise license.jwt file
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +;license_path =
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[/var/opt/gitlab/grafana/provisioning/dashboards/gitlab_dashboards.yml] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/grafana/provisioning/dashboards/gitlab_dashboards.yml
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/grafana/provisioning/dashboards/gitlab_dashboards.yml from none to aa31a1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/grafana/provisioning/dashboards/gitlab_dashboards.yml	2020-01-03 12:39:25.495944411 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/grafana/provisioning/dashboards/.chef-gitlab_dashboards20200103-12696-19p7miy.yml	2020-01-03 12:39:25.495944411 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,12 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +---
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +apiVersion: 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +providers:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: GitLab Omnibus
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  orgId: 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  folder: GitLab Omnibus
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  type: file
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  disableDeletion: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  updateIntervalSeconds: 600
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  options:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +    path: "/opt/gitlab/embedded/service/grafana-dashboards"
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[/var/opt/gitlab/grafana/provisioning/datasources/gitlab_datasources.yml] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - create new file /var/opt/gitlab/grafana/provisioning/datasources/gitlab_datasources.yml
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - update content in file /var/opt/gitlab/grafana/provisioning/datasources/gitlab_datasources.yml from none to 2041c0
module.gitlab.aws_instance.gitlab[0] (remote-exec):     --- /var/opt/gitlab/grafana/provisioning/datasources/gitlab_datasources.yml	2020-01-03 12:39:25.499944411 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +++ /var/opt/gitlab/grafana/provisioning/datasources/.chef-gitlab_datasources20200103-12696-1qdpimr.yml	2020-01-03 12:39:25.499944411 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):     @@ -1 +1,9 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +---
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +apiVersion: 1
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +datasources:
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +- name: GitLab Omnibus
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  type: prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  access: proxy
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  url: http://localhost:9090
module.gitlab.aws_instance.gitlab[0] (remote-exec):     +  isDefault: true
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - change owner from '' to 'gitlab-prometheus'
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[grafana] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[grafana] action enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/grafana] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/grafana/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/grafana/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/grafana/run from none to b54d7b
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/grafana/run	2020-01-03 12:39:25.531944413 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/grafana/.chef-run20200103-12696-1ndu89n	2020-01-03 12:39:25.531944413 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,12 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec 2>&1
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +cd '/var/opt/gitlab/grafana'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +umask 077
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec chpst -P -e /opt/gitlab/etc/grafana/env \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -U gitlab-prometheus:gitlab-prometheus \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  -u gitlab-prometheus:gitlab-prometheus \
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +  /opt/gitlab/embedded/bin/grafana-server -config '/var/opt/gitlab/grafana/grafana.ini'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/grafana/log] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/grafana/log
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/grafana/log/main] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/grafana/log/main
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/grafana/log/run] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /opt/gitlab/sv/grafana/log/run
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /opt/gitlab/sv/grafana/log/run from none to 49180c
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /opt/gitlab/sv/grafana/log/run	2020-01-03 12:39:25.551944414 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /opt/gitlab/sv/grafana/log/.chef-run20200103-12696-1vfcd7u	2020-01-03 12:39:25.551944414 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,3 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +#!/bin/sh
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +exec svlogd -tt /var/log/gitlab/grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/var/log/gitlab/grafana/config] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new file /var/log/gitlab/grafana/config
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - update content in file /var/log/gitlab/grafana/config from none to 623c00
module.gitlab.aws_instance.gitlab[0] (remote-exec):       --- /var/log/gitlab/grafana/config	2020-01-03 12:39:25.567944414 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +++ /var/log/gitlab/grafana/.chef-config20200103-12696-iia8nq	2020-01-03 12:39:25.567944414 +0000
module.gitlab.aws_instance.gitlab[0] (remote-exec):       @@ -1 +1,7 @@
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +s209715200
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +n30
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +t86400
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +!gzip
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       +
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0644'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_grafana] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block verify_chown_persisted_on_grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[verify_chown_persisted_on_grafana] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/grafana/env] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/grafana/env
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[Delete unmanaged env files for grafana service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/grafana/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * template[/opt/gitlab/sv/grafana/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/sv/grafana/control] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create new directory /opt/gitlab/sv/grafana/control
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change mode from '' to '0755'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change owner from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - change group from '' to 'root'
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/init/grafana] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - create symlink at /opt/gitlab/init/grafana to /opt/gitlab/embedded/bin/sv
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/opt/gitlab/sv/grafana/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[restart_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/grafana/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/grafana/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/grafana/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_grafana] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for grafana service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/grafana/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/grafana/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/grafana] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/grafana/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/grafana] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):         - create symlink at /opt/gitlab/service/grafana to /opt/gitlab/sv/grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for grafana service socket] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):         - execute the ruby block wait for grafana service socket
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block restart_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[reload_log_service] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[restart_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[reload_log_service] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/grafana/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana/log] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana/log/main] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/grafana/log/run] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/var/log/gitlab/grafana/config] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[verify_chown_persisted_on_grafana] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana/env] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[Delete unmanaged env files for grafana service] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/grafana/check] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * template[/opt/gitlab/sv/grafana/finish] action create (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/sv/grafana/control] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/init/grafana] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * file[/opt/gitlab/sv/grafana/down] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * link[/opt/gitlab/service/grafana] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       * ruby_block[wait for grafana service socket] action run (skipped due to not_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):       - execute the ruby block reload_log_service
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * directory[/opt/gitlab/service] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/service/grafana] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[wait for grafana service socket] action run (skipped due to not_if)

module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[/opt/gitlab/bin/gitlab-ctl start grafana] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     [execute] ok: run: grafana: (pid 13987) 3s
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl start grafana
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab-ee::sentinel_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * account[user and group for sentinel] action create
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * group[user and group for sentinel] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * linux_user[user and group for sentinel] action create (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[sentinel] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab-ee::sentinel_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[sentinel] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable sentinel] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * file[/var/opt/gitlab/sentinel/sentinel.conf] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * directory[/var/opt/gitlab/sentinel] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[sidekiq-cluster] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab-ee::sidekiq-cluster_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[sidekiq-cluster] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable sidekiq-cluster] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[geo-postgresql] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab-ee::geo-postgresql_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[geo-postgresql] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable geo-postgresql] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[geo-logcursor] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab-ee::geo-logcursor_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[geo-logcursor] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable geo-logcursor] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[pgbouncer] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab-ee::pgbouncer_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[pgbouncer] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable pgbouncer] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[pgbouncer-exporter] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab-ee::pgbouncer-exporter_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[pgbouncer-exporter] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable pgbouncer-exporter] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[consul] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: consul::disable_daemon
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[consul] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable consul] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[repmgrd] action nothing (skipped due to action :nothing)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: repmgr::repmgrd_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[repmgrd] action disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * ruby_block[disable repmgrd] action run (skipped due to only_if)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab-ee::geo-secondary_disable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * templatesymlink[Removes database_geo.yml symlink] action delete
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * file[/var/opt/gitlab/gitlab-rails/etc/database_geo.yml] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):     * link[/opt/gitlab/embedded/service/gitlab-rails/config/database_geo.yml] action delete (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec):      (up to date)
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitlab::gitlab-rails
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[clear the gitlab-rails cache] action run
module.gitlab.aws_instance.gitlab[0]: Still creating... [4m50s elapsed]
module.gitlab.aws_instance.gitlab[0]: Still creating... [5m0s elapsed]

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-rake cache:clear
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[gitaly] action restart

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - restart service service[gitaly]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: gitaly::enable
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * runit_service[gitaly] action hup
module.gitlab.aws_instance.gitlab[0] (remote-exec):     - send hup to runit_service[gitaly]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[gitlab-workhorse] action restart

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - restart service service[gitlab-workhorse]
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[node-exporter] action restart

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - restart service service[node-exporter]
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[gitlab-exporter] action restart

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - restart service service[gitlab-exporter]
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[redis-exporter] action restart

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - restart service service[redis-exporter]
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[prometheus] action restart

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - restart service service[prometheus]
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: monitoring::prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * execute[reload prometheus] action run

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - execute /opt/gitlab/bin/gitlab-ctl hup prometheus
module.gitlab.aws_instance.gitlab[0] (remote-exec): Recipe: <Dynamically Defined Resource>
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[alertmanager] action restart

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - restart service service[alertmanager]
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[postgres-exporter] action restart

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - restart service service[postgres-exporter]
module.gitlab.aws_instance.gitlab[0] (remote-exec):   * service[grafana] action restart

module.gitlab.aws_instance.gitlab[0] (remote-exec):     - restart service service[grafana]
module.gitlab.aws_instance.gitlab[0] (remote-exec):
module.gitlab.aws_instance.gitlab[0] (remote-exec): Running handlers:
module.gitlab.aws_instance.gitlab[0] (remote-exec): Running handlers complete
module.gitlab.aws_instance.gitlab[0] (remote-exec): Chef Client finished, 549/1489 resources updated in 02 minutes 56 seconds
module.gitlab.aws_instance.gitlab[0] (remote-exec): gitlab Reconfigured!
module.gitlab.aws_instance.gitlab[0]: Creation complete after 5m6s [id=i-04484dcf5d1b0e029]
module.dns_cloudflare.cloudflare_record.site_gitlab: Creating...
module.dns_cloudflare.cloudflare_record.site_gitlab: Creation complete after 1s [id=279ff0c22847f839e72e2e201a0b1eea]

Apply complete! Resources: 35 added, 0 changed, 0 destroyed.

Outputs:

gitlab = {
  "gitlab_fqdn" = "tfe-ssc-3-gitlab.guselietov.com"
  "gitlab_private_ip" = [
    "10.0.1.199",
  ]
  "gitlab_public_ip" = [
    "3.125.34.72",
  ]
}
proxy = {
  "proxy_private_ip" = [
    "10.0.1.250",
  ]
  "proxy_public_ip" = [
    "18.185.109.208",
  ]
}
tfe_data = {
  "backend_fqdn" = "tfe-ssc-3_backend.guselietov.com"
  "full_site_url" = "tfe-ssc-3.guselietov.com"
  "loadbalancer_fqdn" = "ag-clb-ag-clb-tfe-ssc-3-1472018554.eu-central-1.elb.amazonaws.com"
  "tfe_instance_public_ip" = "54.93.218.18"
}

```