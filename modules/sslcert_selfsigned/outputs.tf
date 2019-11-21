# Outputs for "sslcert_letsencrypt" module
# note that if you want the full 

output "cert_pem" {
  value = tls_self_signed_cert.tfe.cert_pem
}

output "cert_private_key_pem" {
  value = tls_private_key.tfe.private_key_pem
}

