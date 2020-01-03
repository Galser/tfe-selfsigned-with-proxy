# Log-run for terraform init

```bash
Initializing modules...
- compute_aws in modules/compute_aws
- disk_aws_data in modules/disk_aws
- disk_aws_snapshots in modules/disk_aws
- dns_cloudflare in modules/dns_cloudflare
Downloading github.com/Galser/tf-gitlab-module for gitlab...
- gitlab in .terraform/modules/gitlab
- lb_aws in modules/lb_aws
Downloading github.com/Galser/tf-squid-proxy-module for squidproxy...
- squidproxy in .terraform/modules/squidproxy
- sshkey_aws in modules/sshkey_aws
- sslcert_letsencrypt in modules/sslcert_letsencrypt
- vpc_aws in modules/vpc_aws

Initializing the backend...

Initializing provider plugins...
- Checking for available provider plugins...
- Downloading plugin for provider "cloudflare" (terraform-providers/cloudflare) 2.3.0...
- Downloading plugin for provider "acme" (terraform-providers/acme) 1.5.0...
- Downloading plugin for provider "local" (hashicorp/local) 1.4.0...
- Downloading plugin for provider "tls" (hashicorp/tls) 2.1.1...
- Downloading plugin for provider "aws" (hashicorp/aws) 2.43.0...
- Downloading plugin for provider "null" (hashicorp/null) 2.1.2...

The following providers do not have any version constraints in configuration,
so the latest version was installed.

To prevent automatic upgrades to new major versions that may contain breaking
changes, it is recommended to add version = "..." constraints to the
corresponding provider blocks in configuration, with the constraint strings
suggested below.

* provider.aws: version = "~> 2.43"
* provider.cloudflare: version = "~> 2.3"
* provider.local: version = "~> 1.4"
* provider.null: version = "~> 2.1"
* provider.tls: version = "~> 2.1"

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```