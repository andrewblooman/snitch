variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Deployment environment (e.g. production, staging)"
  type        = string
  default     = "production"
}

variable "bucket_name" {
  description = "S3 bucket name for CI/CD scan results"
  type        = string
  default     = "snitch-cicd-scans"
}

variable "scan_result_retention_days" {
  description = "Days to retain scan result objects in S3"
  type        = number
  default     = 90
}

variable "sqs_message_retention_seconds" {
  description = "SQS message retention period in seconds (default 14 days)"
  type        = number
  default     = 1209600
}

variable "dlq_max_receive_count" {
  description = "Number of times a message is delivered before being sent to the DLQ"
  type        = number
  default     = 3
}
