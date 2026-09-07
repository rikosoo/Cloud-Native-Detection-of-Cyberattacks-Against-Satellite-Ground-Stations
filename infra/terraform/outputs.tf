output "event_stream_name" {
  description = "Kinesis stream the simulator publishes to (gsd simulate --sink kinesis:<name>)."
  value       = aws_kinesis_stream.events.name
}

output "log_group_name" {
  description = "CloudWatch Logs group for the ground station."
  value       = aws_cloudwatch_log_group.station.name
}

output "archive_bucket" {
  description = "S3 bucket holding raw events and CloudTrail logs."
  value       = aws_s3_bucket.archive.bucket
}

output "model_bucket" {
  description = "Upload models/telemetry.json here for the detector Lambda."
  value       = aws_s3_bucket.models.bucket
}

output "detector_function" {
  value = aws_lambda_function.detector.function_name
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "dashboard_url" {
  value = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards:name=${aws_cloudwatch_dashboard.mission.dashboard_name}"
}

output "simulator_access_key_id" {
  description = "Access key for the simulator user, when create_simulator_access_key is true."
  value       = try(aws_iam_access_key.simulator[0].id, null)
}

output "simulator_secret_access_key" {
  description = "Matching secret. Lab only -- prefer assuming a role."
  value       = try(aws_iam_access_key.simulator[0].secret, null)
  sensitive   = true
}
