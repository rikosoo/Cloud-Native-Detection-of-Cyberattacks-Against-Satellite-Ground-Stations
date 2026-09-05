resource "aws_sns_topic" "alerts" {
  name              = "${local.prefix}-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Any CRITICAL finding pages the on-call operator immediately: at this severity
# the spacecraft itself is at risk, so the alarm treats missing data as normal
# but fires on a single datapoint.
resource "aws_cloudwatch_metric_alarm" "critical_findings" {
  alarm_name          = "${local.prefix}-critical-findings"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = 1
  period              = 60
  statistic           = "Sum"
  namespace           = "GroundStation/Detection"
  metric_name         = "CriticalFindings"
  treat_missing_data  = "notBreaching"
  alarm_description   = "A CRITICAL ground-station finding was raised (command integrity, replay or exfiltration)."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = {
    StationId = var.station_id
  }
}

# Telemetry silence is itself an incident: a jammed or hijacked downlink stops
# producing events long before anything else shows up.
resource "aws_cloudwatch_metric_alarm" "telemetry_gap" {
  alarm_name          = "${local.prefix}-telemetry-gap"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  threshold           = 1
  period              = 300
  statistic           = "Sum"
  namespace           = "GroundStation/Detection"
  metric_name         = "EventsProcessed"
  treat_missing_data  = "breaching"
  alarm_description   = "No ground-station events processed for 10 minutes."
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    StationId = var.station_id
  }
}

resource "aws_cloudwatch_metric_alarm" "detector_errors" {
  alarm_name          = "${local.prefix}-detector-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 0
  period              = 300
  statistic           = "Sum"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  treat_missing_data  = "notBreaching"
  alarm_description   = "The detection Lambda is failing; detections are being lost."
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.detector.function_name
  }
}

resource "aws_cloudwatch_dashboard" "mission" {
  dashboard_name = "${local.prefix}-ground-station"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          title  = "Detections by severity"
          region = var.region
          stat   = "Sum"
          period = 300
          metrics = [
            ["GroundStation/Detection", "FindingsEmitted", "StationId", var.station_id],
            [".", "CriticalFindings", ".", "."]
          ]
        }
      },
      {
        type   = "metric"
        width  = 12
        height = 6
        properties = {
          title  = "Event throughput"
          region = var.region
          stat   = "Sum"
          period = 300
          metrics = [
            ["GroundStation/Detection", "EventsProcessed", "StationId", var.station_id],
            ["AWS/Kinesis", "IncomingRecords", "StreamName", aws_kinesis_stream.events.name]
          ]
        }
      },
      {
        type   = "log"
        width  = 24
        height = 6
        properties = {
          title  = "Recent findings"
          region = var.region
          query  = "SOURCE '/aws/lambda/${local.prefix}-detector' | fields @timestamp, @message | filter @message like /rules=/ | sort @timestamp desc | limit 50"
        }
      }
    ]
  })
}
