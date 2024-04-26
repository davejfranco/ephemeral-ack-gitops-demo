locals {
  prefix = "eph-demo"

  network = {
    cidr = "172.16.0.0/16"
    az   = [for zone in slice(data.aws_availability_zones.current.names, 0, 3) : zone]
  }

  default_tags = {
    Terraform   = "true"
    Environment = "demo"
  }
}
