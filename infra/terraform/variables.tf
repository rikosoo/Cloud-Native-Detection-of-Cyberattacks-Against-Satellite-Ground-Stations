variable "region" {
  description = "AWS region hosting the ground-segment workload."
  type        = string
  default     = "sa-east-1"
}

variable "environment" {
  description = "Deployment environment (lab, staging, prod)."
  type        = string
  default     = "lab"
}

variable "name_prefix" {
  description = "Prefix applied to every resource name."
  type        = string
  default     = "gsd"
}

variable "station_id" {
  description = "Identifier of the simulated ground station."
  type        = string
  default     = "SENTINEL-GS"
}

variable "alert_email" {
  description = "Address subscribed to the SNS alert topic. Empty disables the subscription."
  type        = string
  default     = ""
}

variable "kinesis_shard_count" {
  description = "Shards on the telemetry ingestion stream."
  type        = number
  default     = 1
}

variable "log_retention_days" {
  description = "Retention for the ground-station log group."
  type        = number
  default     = 90
}

variable "replay_memory_days" {
  description = "How long the replay dedupe table remembers a telecommand frame."
  type        = number
  default     = 2
}

variable "enable_guardduty" {
  description = "Create a GuardDuty detector. Set to false if the account already has one."
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable Security Hub in this account/region."
  type        = bool
  default     = true
}

variable "lambda_layer_zip" {
  description = "Path to the gsd Lambda layer archive (see infra/build_layer.sh)."
  type        = string
  default     = "../../build/gsd-layer.zip"
}
