output "s3_bucket_name" {
  description = "S3 bucket for CI/CD scan results"
  value       = aws_s3_bucket.cicd_scans.bucket
}

output "sqs_queue_url" {
  description = "SQS queue URL — set as SQS_CICD_QUEUE_URL in Snitch"
  value       = aws_sqs_queue.cicd_scans.url
}

output "sqs_dlq_url" {
  description = "Dead-letter queue URL for failed messages"
  value       = aws_sqs_queue.cicd_scans_dlq.url
}

output "snitch_worker_access_key_id" {
  description = "AWS_ACCESS_KEY_ID for the Snitch worker service"
  value       = aws_iam_access_key.snitch_worker.id
}

output "snitch_worker_secret_access_key" {
  description = "AWS_SECRET_ACCESS_KEY for the Snitch worker service"
  value       = aws_iam_access_key.snitch_worker.secret
  sensitive   = true
}

output "cicd_uploader_access_key_id" {
  description = "AWS_ACCESS_KEY_ID for CI/CD pipelines uploading scan results"
  value       = aws_iam_access_key.cicd_uploader.id
}

output "cicd_uploader_secret_access_key" {
  description = "AWS_SECRET_ACCESS_KEY for CI/CD pipelines uploading scan results"
  value       = aws_iam_access_key.cicd_uploader.secret
  sensitive   = true
}
