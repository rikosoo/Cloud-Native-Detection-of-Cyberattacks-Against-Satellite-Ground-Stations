# --- CloudTrail: the source of truth for the identity plane -----------------
resource "aws_cloudtrail" "ground_segment" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.archive.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_logs.arn

  # Advanced event selectors REPLACE the default management-event selector, so
  # this one has to be declared explicitly -- without it CloudTrail records no
  # ConsoleLogin / CreateAccessKey / DeleteTrail at all and the whole GS-AUTH-*
  # catalogue goes silent against a real account.
  advanced_event_selector {
    name = "management-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # Data events on the mission archive are what make bulk-exfiltration
  # detection (GS-EXF-003) possible at all.
  advanced_event_selector {
    name = "mission-archive-data-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.archive.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail]
}

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/ground-station/${var.station_id}/cloudtrail"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "trail_to_logs" {
  name = "${local.prefix}-trail-to-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "trail_to_logs" {
  name = "${local.prefix}-trail-to-logs"
  role = aws_iam_role.trail_to_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
    }]
  })
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.archive.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/cloudtrail/AWSLogs/${local.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.archive.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

# --- GuardDuty: AWS-native behavioural detection ----------------------------
resource "aws_guardduty_detector" "this" {
  count                        = var.enable_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

# --- Security Hub: single pane for GuardDuty + our own findings -------------
resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0
}

resource "aws_securityhub_standards_subscription" "foundational" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_product_subscription" "guardduty" {
  count       = var.enable_security_hub && var.enable_guardduty ? 1 : 0
  product_arn = "arn:aws:securityhub:${var.region}::product/aws/guardduty"
  depends_on  = [aws_securityhub_account.this]
}
