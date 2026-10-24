# Minimal AWS footprint for the payments API. Never applied in the demo:
# Checkov reads it statically, so no AWS account or credentials are needed.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "ap-south-1"
}

variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }

# ---------------------------------------------------------------------------
# Cardholder-data export bucket
# PLANTED ISSUES: no KMS encryption (PCI 3.5.1 / A.8.24),
#                 no access logging (PCI 10.2.1 / A.8.15)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "card_exports" {
  bucket = "payments-demo-card-exports"
}

resource "aws_s3_bucket_public_access_block" "card_exports" {
  bucket                  = aws_s3_bucket.card_exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Database
# PLANTED ISSUE: storage not encrypted (PCI 3.5.1 / A.8.24)
# ---------------------------------------------------------------------------
resource "aws_db_instance" "payments" {
  identifier          = "payments-db"
  engine              = "postgres"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  username            = "payments"
  manage_master_user_password = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

# ---------------------------------------------------------------------------
# Network
# PLANTED ISSUE: SSH open to the internet (PCI 1.3.1 / A.8.20)
# ---------------------------------------------------------------------------
resource "aws_security_group" "api" {
  name        = "payments-api"
  description = "Payments API instances"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description     = "App traffic from the load balancer"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Outbound HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "alb" {
  name        = "payments-alb"
  description = "Public load balancer"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "To app instances"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# ---------------------------------------------------------------------------
# Load balancer
# PLANTED ISSUES: plain-HTTP listener (PCI 4.2.1 / A.8.24),
#                 no ALB access logs (PCI 10.2.1 / A.8.15)
# ---------------------------------------------------------------------------
resource "aws_lb" "api" {
  name                       = "payments-api"
  load_balancer_type         = "application"
  subnets                    = var.subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}

resource "aws_lb_target_group" "api" {
  name     = "payments-api"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = var.vpc_id
}

resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.api.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
