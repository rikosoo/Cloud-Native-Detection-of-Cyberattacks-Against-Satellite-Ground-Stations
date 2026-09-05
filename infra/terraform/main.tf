data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  prefix     = "${var.name_prefix}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
}
