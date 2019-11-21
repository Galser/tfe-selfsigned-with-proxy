output "cert_url" {
  #value = "${module.sslcert_letsencrypt.cert_url}"
  value = "CERTIFICATE GENERATION IS DISABLED"
}

output "public_ip" {
  value = "${module.compute_aws.public_ip}"
}

output "full_site_name" {
  value = "${var.site_record}.${var.site_domain}"
}

output "loadbalancer_fqdn" {
  value       = module.lb_aws.fqdn
  description = "The domain name of the load balancer"
}

output "backend_fqdn" {
  value = "${module.dns_cloudflare.backend_fqdn}"
}

output "region" {
  value = "${var.region}"
}

