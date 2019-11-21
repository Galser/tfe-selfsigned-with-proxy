# Self Signed cert module

A terraform module to create SSL Cert for the given DNS record


## Inputs
- **domain**  *[String]* -  Domain for the record
- **host**  *[String]* -  Host part for the record

## Outputs
- **cert_pem** - *strng* - PEM-encoded Certificate
- **cert_private_key_pem** - *strng* - PEM-encoded private key
- **cert_issuer_pem** - *strng* - PEM-encoded Issuer Cert
- **cert_bundle** - *strng* - PEM-Encoded bundle



