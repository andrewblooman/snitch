# ─── SQS Dead-Letter Queue ────────────────────────────────────────────────────

resource "aws_sqs_queue" "cicd_scans_dlq" {
  name                      = "snitch-cicd-scans-dlq"
  message_retention_seconds = var.sqs_message_retention_seconds

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ─── SQS Main Queue ───────────────────────────────────────────────────────────

resource "aws_sqs_queue" "cicd_scans" {
  name                      = "snitch-cicd-scans"
  message_retention_seconds = var.sqs_message_retention_seconds

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.cicd_scans_dlq.arn
    maxReceiveCount     = var.dlq_max_receive_count
  })

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Allow S3 to send messages to this queue
resource "aws_sqs_queue_policy" "cicd_scans_s3_policy" {
  queue_url = aws_sqs_queue.cicd_scans.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3SendMessage"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.cicd_scans.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:s3:::${var.bucket_name}"
          }
        }
      }
    ]
  })
}

# ─── S3 Bucket ────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "cicd_scans" {
  bucket = var.bucket_name

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_s3_bucket_versioning" "cicd_scans" {
  bucket = aws_s3_bucket.cicd_scans.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cicd_scans" {
  bucket = aws_s3_bucket.cicd_scans.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cicd_scans" {
  bucket                  = aws_s3_bucket.cicd_scans.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cicd_scans" {
  bucket = aws_s3_bucket.cicd_scans.id

  rule {
    id     = "expire-scan-results"
    status = "Enabled"

    expiration {
      days = var.scan_result_retention_days
    }
  }
}

# S3 event notification → SQS on any object created
resource "aws_s3_bucket_notification" "cicd_scans" {
  bucket = aws_s3_bucket.cicd_scans.id

  queue {
    queue_arn = aws_sqs_queue.cicd_scans.arn
    events    = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_sqs_queue_policy.cicd_scans_s3_policy]
}
