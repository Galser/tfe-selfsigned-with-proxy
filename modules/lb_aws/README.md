# lb_aws module

Create classical ELB in AWS for TFE

# Parameters 
 
- **name** - Stering - just name , postfix actually to some predefined value
- **subnets** - List of subnets
- **security_groups** - List of security groups
- **instances** - List of instances IDs

# Attributes 

- **fqdn** - The FQDN of the load balancer