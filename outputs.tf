output tfe_data {
  value = {
    full_site_url = "${var.site_record}.${var.site_domain}"
    #    cert_url = "REAL CERTIFICATE GENERATION IS DISABLED"
    loadbalancer_fqdn      = module.lb_aws.fqdn
    tfe_instance_public_ip = module.compute_aws.public_ip
    backend_fqdn           = module.dns_cloudflare.backend_fqdn
  }
}

output "proxy" {
  value = {
    proxy_public_ip  = module.squidproxy.public_ips
    proxy_private_ip = module.squidproxy.private_ip
  }
}

output "gitlab" {
  value = {
    gitlab_public_ip  = module.gitlab.public_ips
    gitlab_private_ip = module.gitlab.private_ip
    gitlab_fqdn       = "${var.site_record}-gitlab.${var.site_domain}"
  }
}
