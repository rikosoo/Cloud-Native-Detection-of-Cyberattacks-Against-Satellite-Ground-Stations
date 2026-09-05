data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "detector" {
  name               = "${local.prefix}-detector"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Least privilege: read the stream and the model, dedupe in one table, import
# findings. No write access to the archive, no wildcard resources.
data "aws_iam_policy_document" "detector" {
  statement {
    sid       = "ReadEventStream"
    effect    = "Allow"
    actions   = ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary", "kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:ListShards", "kinesis:SubscribeToShard"]
    resources = [aws_kinesis_stream.events.arn]
  }

  statement {
    sid       = "ReplayMemory"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.replay_memory.arn]
  }

  statement {
    sid       = "ReadBaselineModel"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.models.arn}/*"]
  }

  statement {
    sid       = "PublishFindings"
    effect    = "Allow"
    actions   = ["securityhub:BatchImportFindings"]
    resources = ["arn:aws:securityhub:${var.region}:${local.account_id}:product/${local.account_id}/default"]
  }

  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${local.prefix}-detector:*"]
  }

  statement {
    sid       = "DecryptStreamAndModel"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["kinesis.${var.region}.amazonaws.com", "s3.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "detector" {
  name   = "${local.prefix}-detector"
  role   = aws_iam_role.detector.id
  policy = data.aws_iam_policy_document.detector.json
}

resource "aws_iam_role" "guardduty_router" {
  name               = "${local.prefix}-guardduty-router"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "guardduty_router" {
  statement {
    effect    = "Allow"
    actions   = ["securityhub:BatchImportFindings"]
    resources = ["arn:aws:securityhub:${var.region}:${local.account_id}:product/${local.account_id}/default"]
  }

  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/aws/lambda/${local.prefix}-guardduty-router:*"]
  }
}

resource "aws_iam_role_policy" "guardduty_router" {
  name   = "${local.prefix}-guardduty-router"
  role   = aws_iam_role.guardduty_router.id
  policy = data.aws_iam_policy_document.guardduty_router.json
}

# Identity used by the simulator to publish events. Deliberately write-only on
# the stream: a compromised simulator must not be able to read the archive.
resource "aws_iam_user" "simulator" {
  name = "${local.prefix}-simulator"
}

resource "aws_iam_user_policy" "simulator" {
  name = "${local.prefix}-simulator"
  user = aws_iam_user.simulator.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kinesis:PutRecord", "kinesis:PutRecords"]
        Resource = aws_kinesis_stream.events.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.station.arn}:*"
      }
    ]
  })
}
