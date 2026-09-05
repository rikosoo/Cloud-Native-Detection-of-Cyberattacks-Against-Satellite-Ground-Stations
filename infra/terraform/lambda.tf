data "archive_file" "detector" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/detector"
  output_path = "${path.module}/.build/detector.zip"
}

data "archive_file" "guardduty_router" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/guardduty_router"
  output_path = "${path.module}/.build/guardduty_router.zip"
}

# The gsd package (engine, rules, model) ships as a layer so the two functions
# and the offline CLI stay byte-identical. Build it with infra/build_layer.sh.
resource "aws_lambda_layer_version" "gsd" {
  layer_name          = "${local.prefix}-gsd"
  filename            = var.lambda_layer_zip
  source_code_hash    = filebase64sha256(var.lambda_layer_zip)
  compatible_runtimes = ["python3.11"]
  description         = "gsd detection engine, rules catalogue and telemetry model loader"
}

resource "aws_lambda_function" "detector" {
  function_name    = "${local.prefix}-detector"
  role             = aws_iam_role.detector.arn
  handler          = "handler.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  timeout          = 60
  memory_size      = 512
  layers           = [aws_lambda_layer_version.gsd.arn]

  environment {
    variables = {
      AWS_ACCOUNT_ID   = local.account_id
      STATE_TABLE      = aws_dynamodb_table.replay_memory.name
      MODEL_BUCKET     = aws_s3_bucket.models.bucket
      MODEL_KEY        = "models/telemetry.json"
      STATION_ID       = var.station_id
      METRIC_NAMESPACE = "GroundStation/Detection"
      LOG_LEVEL        = "INFO"
    }
  }
}

resource "aws_lambda_event_source_mapping" "detector" {
  event_source_arn                   = aws_kinesis_stream.events.arn
  function_name                      = aws_lambda_function.detector.arn
  starting_position                  = "LATEST"
  batch_size                         = 200
  maximum_batching_window_in_seconds = 10
  maximum_retry_attempts             = 3
  bisect_batch_on_function_error     = true

  function_response_types = ["ReportBatchItemFailures"]
}

resource "aws_lambda_function" "guardduty_router" {
  function_name    = "${local.prefix}-guardduty-router"
  role             = aws_iam_role.guardduty_router.arn
  handler          = "handler.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.guardduty_router.output_path
  source_code_hash = data.archive_file.guardduty_router.output_base64sha256
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      AWS_ACCOUNT_ID = local.account_id
      STATION_ID     = var.station_id
      LOG_LEVEL      = "INFO"
    }
  }
}

# Every GuardDuty finding is re-scored against the mission asset inventory.
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${local.prefix}-guardduty-findings"
  description = "Route GuardDuty findings to the ground-station correlator"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "guardduty-router"
  arn       = aws_lambda_function.guardduty_router.arn
}

resource "aws_lambda_permission" "guardduty" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardduty_router.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}
