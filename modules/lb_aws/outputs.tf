output "fqdn" {
  value       = aws_elb.ptfe_lb.dns_name
  description = "The FQDN of the load balancer"
}
