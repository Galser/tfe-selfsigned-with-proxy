resource "tls_private_key" "tfe" {
  algorithm = "ECDSA"
}

resource "tls_self_signed_cert" "tfe" {
  key_algorithm   = "ECDSA"
  private_key_pem = tls_private_key.tfe.private_key_pem

  subject {
    common_name  = "${var.host}.${var.domain}"
    organization = "HashiCorp demo"
  }

  dns_names = ["${var.host}.${var.domain}"]

  validity_period_hours = 24 * 30 # 30 days

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# to make life easier when installing
resource "local_file" "ssl_private_key_file" {
  sensitive_content = "${tls_private_key.tfe.private_key_pem}"
  filename          = "./site_ssl_private_key.pem"
}

resource "local_file" "ssl_cert_file" {
  sensitive_content = "${tls_self_signed_cert.tfe.cert_pem}"
  filename          = "./site_ssl_cert.pem"
}

