# Load-Balancer, AWS ELB classic  as we terminate SSL
# on instance and no need for new features of ALB
resource "aws_elb" "ptfe_lb" {
  name = "ag-clb-${var.name}"

  security_groups = var.security_groups
  subnets         = var.subnets

  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 10
    timeout             = 10
    target              = "TCP:8800"
    interval            = 30
  }

  listener {
    instance_port      = "443"
    instance_protocol  = "https"
    lb_port            = "443"
    lb_protocol        = "https"
    ssl_certificate_id = var.ssl_certificate_id
  }
  listener {
    instance_port      = "8800"
    instance_protocol  = "https"
    lb_port            = "8800"
    lb_protocol        = "https"
    ssl_certificate_id = var.ssl_certificate_id
  }

  instances                   = var.instances
  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400

  tags = {
    "Name"      = "${var.name}",
    "andriitag" = "true",
    #"learntag"  = "${var.learntag}"
  }
}
