data "cloudflare_zones" "site_zone" {
  filter {
    name = var.domain
  }
}

locals {
  backend = "${var.host}_backend"
  #proxy        = "${var.host}-proxy"
  gitlab         = "${var.host}-gitlab"
  domain_zone_id = lookup(data.cloudflare_zones.site_zone.zones[0], "id")
}

resource "cloudflare_record" "site_backend" {
  zone_id = local.domain_zone_id
  name    = local.backend
  value   = var.record_ip
  type    = "A"
  ttl     = 600
}

resource "cloudflare_record" "site_lb" {
  zone_id = local.domain_zone_id
  name    = var.host
  value   = var.cname_target
  type    = "CNAME"
  ttl     = 600
}

resource "cloudflare_record" "site_gitlab" {
  zone_id = local.domain_zone_id
  name    = local.gitlab
  value   = var.gitlab_ip
  type    = "A"
  ttl     = 600
}
