# tfe-selfsigned-with-proxy
Choose one install you feel comfortable with, and use proxy and git (gitlab or bitbucket) all with self signed ssl cert 

Based on: https://github.com/Galser/ptfe-prodmount-vc-cloud-backuprestore

# Purpose

This repo contains all the code and instructions on how to install a TFE (Prod) version with a Self-Signed Certificate in an AWS cloud environment in diskmount mode with a proxy in fron of it and later, how to setup and test VCS connection. 

# Requirements

This repository assumes general knowledge about Terraform, if not, please get yourself accustomed first by going through [getting started guide for Terraform](https://learn.hashicorp.com/terraform?track=getting-started#getting-started). We also going to use AWS EC2 as our infrastructure provider, DNS service of CloudFlare.

To learn more about the mentioned above tools and technologies - please check section [Technologies near the end of the README](#technologies)


# How-to

## Prepare authentication credentials
- Beforehand, you will need to have SSH RSA key available at the default location :
 - `~/.ssh/id_rsa` and `~/.ssh/id_rsa.pub`
 > This key is going to be used later to connect to the instance where TFE will be running.
 
- Prepare AWS auth credentials (You can create security credentials on [this page](https://console.aws.amazon.com/iam/home?#security_credential).) To export them via env variables, execute in the command line :
 ```
 export AWS_ACCESS_KEY_ID="YOUR ACCESS KEY"
 export AWS_SECRET_ACCESS_KEY="YOUR SECRET KEY"
 ```
- Prepare CloudFlare authentication for your domain DNS management - register and export as env variables API keys and tokens. Follow instructions from CloudFlare here: https://support.cloudflare.com/hc/en-us/articles/200167836-Managing-API-Tokens-and-Keys
 - Export generated token and API keys :
 ```bash
 export CLOUDFLARE_API_KEY=YOUR_API_KEY_HERE
 export CLOUDFLARE_API_TOKEN=YOUR_TOKEN_HERE
 export CLOUDFLARE_ZONE_API_TOKEN=YOUR_TOKEN_HERE
 export CLOUDFLARE_DNS_API_TOKEN=YOUR_TOKEN_HERE
 ```

## Deploy infrastructure
- Clone this repo (*use the tools of your choice*)
- Open the folder with cloned repo
- init
- apply 

## Install TFE

q### Terminal-based portion of TFE installation

- Connect to VM :
```bash
ssh ubuntu@tfe-ssc-3_backend.guselietov.com
```
> Note: Use the `public_ip` or `backend_fqdn` from the previous step

- Start the PTFE install:

curl https://install.terraform.io/ptfe/stable  > install.sh
sudo bash ./install.sh http-proxy=http://10.0.1.66:3128

```curl https://install.terraform.io/ptfe/stable | sudo bash```
 - use Public IP-address from previous steps ( `18.184.74.49` in the example ) for the service question. You can just press [Enter],
 - Reply `N` to proxy question. Again - you can just press [Enter]
 Output example :
 ```bash
   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  133k  100  133k    0     0  30975      0  0:00:04  0:00:04 --:--:-- 30975
Determining local address
The installer will use network interface 'ens5' (with IP address '10.0.1.67')
Determining service address
The installer will use service address '18.184.74.49' (discovered from EC2 metadata service)
The installer has automatically detected the service IP address of this machine as 18.184.74.49.
Do you want to:
[0] default: use 18.184.74.49
[1] enter new address...
...

 Operator installation successful

 To continue the installation, visit the following URL in your browser:

 http://18.184.74.49:8800

 ```
This concludes the terminal install portion. let's continue in Web UI.

### Terminal-based portion of TFE installation

### Web-based portion of TFE installation

## Configure workspace and attach VCS

## Test commits


# TODO
- [ ] return normal certificate for the proxy - as this is allowed for this task
- [ ] go back to nginx, apparently SQUID in Ubuntu 18.04 now is a bummer
due to open-ssl not compiled by default
- [ ] test with proxy
- [ ] connect VCS , make screenshots
- [ ] update README for VCS part
- [ ] create/import tests for TFE
- [ ] test commits of tests against custom VCS, save logs & screenshots
- [ ] update README for tests
- [ ] final README update


# DONE
- [x] define objectives 
- [x] reuse code for compute infra
- [x] import mount disk (EBS) code as module, test
- [x] create code for self-signed cert generation
- [x] decide on various proxy. test them - ELB, Nginx, Squid, Oops and etc.
- [x] create code for proxy deploy
- [x] deploy proxy, tweak DNS if required
- [x] install TFE in Prod mode


# Run logs

- terraform init : [terraform_init.md](terraform_init.md)
- terraform apply : [terraform_apply.md](terraform_apply.md)
- terraform destroy  : [terraform_destroy.md](terraform_destroy.md)


# Technologies

1. **To download the content of this repository** you will need **git command-line tools**(recommended) or **Git UI Client**. To install official command-line Git tools please [find here instructions](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for various operating systems. 

2. **For managing infrastructure** we using Terraform - open-source infrastructure as a code software tool created by HashiCorp. It enables users to define and provision a data center infrastructure using a high-level configuration language known as Hashicorp Configuration Language, or optionally JSON. More you encouraged to [learn here](https://www.terraform.io).
 - Specifically, we going to use Terraform for creating infrastructure, and install Terraform Enterprise. TFE Overview: can be found here: https://www.terraform.io/docs/enterprise/index.html
 - Pre-Install checklist: https://www.terraform.io/docs/enterprise/before-installing/index.html

3. **This project for virtualization** uses **AWS EC2** - Amazon Elastic Compute Cloud (Amazon EC2 for short) - a web service that provides secure, resizable compute capacity in the cloud. It is designed to make web-scale cloud computing easier for developers. You can read in details and create a free try-out account if you don't have one here : [Amazon EC2 main page](https://aws.amazon.com/ec2/) 

4. **Cloudflare**, - is an American web infrastructure and website security company, providing content delivery network services, DDoS mitigation, Internet security, and distributed domain name server services. More information can be found here: https://www.cloudflare.com/ 

5. **ButBucket Server** -  is self-hosted Git repository collaboration and management for professional teams. You can check more in details here : https://confluence.atlassian.com/bitbucketserver


