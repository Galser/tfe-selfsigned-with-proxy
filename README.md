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
- Define your domain name in [variables.tf](variables.tf), edit on 2-nd line, following block :
 ```terraform
 variable "site_domain" {
   default = "guselietov.com"
 }
 ```
- Define your domain site (host) record in [variables.tf](variables.tf), edit on 6-s line, following block :
 ```terraform
 variable "site_record" {
   default = "tfe-ssc-3"
 }
 ```

- From inside folder with cloned repo init Terraform by executing :
```
terraform init
```
Example output can be found here : [terraform_init.md](terraform_init.md)

- Now let's spin up everything, by executing :
```
terraform apply -auto-approve
```
Example FULL output can be found here : [terraform_apply.md](terraform_apply.md)

Execution will take some time, and at the very end of the output you should see something similar to :
```bash
Outputs:

gitlab = {
  "gitlab_private_ip" = [
    "10.0.1.177",
  ]
  "gitlab_public_ip" = [
    "35.157.218.64",
  ]
}
proxy = {
  "proxy_private_ip" = [
    "10.0.1.66",
  ]
  "proxy_public_ip" = [
    "18.194.28.150",
  ]
}
tfe_data = {
  "backend_fqdn" = "tfe-ssc-3_backend.guselietov.com"
  "full_site_url" = "tfe-ssc-3.guselietov.com"
  "loadbalancer_fqdn" = "ag-clb-ag-clb-tfe-ssc-3-177845966.eu-central-1.elb.amazonaws.com"
  "tfe_instance_public_ip" = "3.122.205.219"
}
```

## Install TFE

### Terminal-based portion of TFE installation

- Connect to VM :
```bash
ssh ubuntu@tfe-ssc-3_backend.guselietov.com
```
> Note: Use the `public_ip` or `backend_fqdn` from the previous step

- We want to ensure using of the proxy from the very beginning. So instead of one-liner that downloads and runs installation script, we are going to do two steps: 

  - Download installation script by executing : 
  ```
  curl https://install.terraform.io/ptfe/stable  > install.sh
  ```
  - Run it with specifying proxy parameter, the IP-address of the proxy can be found in the output section of `terraform apply` above - `proxy_private_ip`. Execute : 
```
sudo bash ./install.sh http-proxy=http://10.0.1.66:3128
```

 - use Public IP-address from previous steps ( `3.122.205.219` in the example ) for the service question. You can just press [Enter],
 - Reply `N` to proxy question. Again - you can just press [Enter]
 Output example :
 ```bash
   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  133k  100  133k    0     0  30975      0  0:00:04  0:00:04 --:--:-- 30975
Determining local address
The installer will use network interface 'ens5' (with IP address '10.0.1.67')
Determining service address
The installer will use service address '3.122.205.219' (discovered from EC2 metadata service)
The installer has automatically detected the service IP address of this machine as 3.122.205.219.
Do you want to:
[0] default: use 3.122.205.219
[1] enter new address...
...

 Operator installation successful

 To continue the installation, visit the following URL in your browser:

 http://3.122.205.219:8800

 ```
This concludes the terminal install portion. let's continue in Web UI.

### Web-based portion of TFE installation

- Open your favorite browser and access the link that had been presented to you at the previous step: http://3.122.205.219:8800,  As we using self-signed certificates for this part of the installation, you will see a security warning when first connecting. **This is expected and you'll need to proceed with the connection anyway.**
- Now you will be presented with settings screen where you will need to enter hostname: `tfe-ssc-3.guselietov.com` *( this used in the example, you may have another one if you modified settings earlier)* and press button **[Use Self-Signed Cert]**

   > Sometimes, depending on the speed of instance connection and external resources replies you will fail to access this screen because load-balancer could not detect that Terraform Dashboard already running and removed it from service. Just wait 30 seconds and refresh the page.
- In the next step - you need to present your license file. Usually, it comes in a special tar-ball package with extension RLI. Press **[Choose license]**, Locate the file and upload.
- The next screen allows you to select between *Online* and *air-gapped* installation. Choose **[Online]** and press **[Continue]** button
- At the next step, you will need to enter the password, that can be used in the future to access THIS, Admin Console. Enter the desired password, and press **[continue]**
- Now you will see the *"Preflight Checks"* when all the main requirements for the PTFE installation checked and the one that passed marked with a green checkmark. They ALL should be green to pass.
Once more, press **[Continue]** button
- The next screen presents all your settings in one place
    - Check that host FQDN is correct
    - Scroll down to the *Installation Type* section and select **[Production]**
    - Now in the next section *Production Type* select **[Mounted Disk]**
    - Below it, in the *Mounted Disk Configuration* enter path : `/tfe-data`

    Consult the screenshot for guidance :

    ![Prod Settings](screenshots/3_3_settings_prod.png)
   After that - press **[Save]** button at the bottom of the page to save all your settings. And you going to be present with the following informational screen :
![Settings saved, restart now](screenshots/4_restat_now.png)
 Press **[Restart Now]**
- At this moment PTFE will do a full start of all internal services, it can take a couple of minutes, refresh the windows from time to time :
![Starting dashboard](screenshots/5_starting.png)
  > Note:..Depending on your browser and/or browser settings the starting in the left part of Dashboard - never changes unless you reload the page. So force-reload the page after 2-3 minutes.
- While TFE starting, please access top-right menu with settings, "Console Settings" item. In the opened page, find section *Snapshot & Restore*. In the filed **"Snapshot File Destination"** enter : `/tfe-snapshots`.
Press blue **[Save]** button at the bottom of the page.
- You can double-check that proxy is used at the section "HTTP Proxy" : 

    ![Proxy](screenshots/proxy-double-check.png)

- Return to the dashboard. Wait a couple of minutes for the state at the left rectangle to be changed to **Started**. Now, below the button [Stop now] there is link **[Open]** :

    ![Started](screenshots/6_started.png)

    Open it, this will lead you to the first-time setup of the admin user :
- Set up your admin user :

    ![Setup admin user](screenshots/7_admin_setup.png)

    Fill in the form and press **[Create an account]**
- Now you are logged in the brand fresh Private Terraform Enterprise. Congratulations. You can check the next section on how to test it.


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


