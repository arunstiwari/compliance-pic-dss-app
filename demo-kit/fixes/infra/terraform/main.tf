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
variable "admin_cidr" {
  type        = string
  description = "Corporate VPN range allowed to reach SSH"
  default     = "10.20.0.0/16"
}
variable "certificate_arn" { type = string }

resource "aws_kms_key" "data" {
  description         = "Encrypts cardholder data at rest"
  enable_key_rotation = true
}

# ---------------------------------------------------------------------------
# Cardholder-data export bucket
# FIXED: KMS encryption (PCI 3.5.1 / A.8.24), access logging (PCI 10.2.1 / A.8.15)
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

resource "aws_s3_bucket_server_side_encryption_configuration" "card_exports" {
  bucket = aws_s3_bucket.card_exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_s3_bucket" "access_logs" {
  # Documented exception, shown as "accepted exception" in the compliance matrix:
  #checkov:skip=CKV_AWS_145:ALB access-log delivery only supports SSE-S3, so this bucket uses AES256 (risk accepted, ticket SEC-142)
  bucket = "payments-demo-access-logs"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "card_exports" {
  bucket        = aws_s3_bucket.card_exports.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3/card-exports/"
}

# ---------------------------------------------------------------------------
# Database
# FIXED: encrypted storage (PCI 3.5.1 / A.8.24), engine logs exported (PCI 10.2.1 / A.8.15)
# ---------------------------------------------------------------------------
resource "aws_db_instance" "payments" {
  identifier                      = "payments-db"
  engine                          = "postgres"
  instance_class                  = "db.t4g.micro"
  allocated_storage               = 20
  username                        = "payments"
  manage_master_user_password     = true
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.data.arn
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  skip_final_snapshot             = true
}

# ---------------------------------------------------------------------------
# Network
# FIXED: SSH only from the corporate VPN range (PCI 1.3.1 / A.8.20)
# ---------------------------------------------------------------------------
resource "aws_security_group" "api" {
  name        = "payments-api"
  description = "Payments API instances"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from corporate VPN only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
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
# FIXED: HTTPS with TLS 1.2+ (PCI 4.2.1 / A.8.24), access logs (PCI 10.2.1 / A.8.15),
#        WAF in front of the public app (PCI 6.4.2 / A.8.20)
# ---------------------------------------------------------------------------
resource "aws_lb" "api" {
  name                       = "payments-api"
  load_balancer_type         = "application"
  subnets                    = var.subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.access_logs.id
    prefix  = "alb"
    enabled = true
  }
}

resource "aws_lb_target_group" "api" {
  name     = "payments-api"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = var.vpc_id
}

resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_wafv2_web_acl" "api" {
  name  = "payments-api"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-common"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "payments-api"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "api" {
  resource_arn = aws_lb.api.arn
  web_acl_arn  = aws_wafv2_web_acl.api.arn
}
