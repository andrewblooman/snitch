# ─── IAM: Snitch worker (SQS consume + S3 read) ─────────────────────────────

resource "aws_iam_user" "snitch_worker" {
  name = "snitch-worker"
  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_access_key" "snitch_worker" {
  user = aws_iam_user.snitch_worker.name
}

resource "aws_iam_user_policy" "snitch_worker" {
  name = "snitch-worker-cicd-scans"
  user = aws_iam_user.snitch_worker.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReceiveDeleteSQS"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
        ]
        Resource = aws_sqs_queue.cicd_scans.arn
      },
      {
        Sid    = "GetS3Objects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
        ]
        Resource = "${aws_s3_bucket.cicd_scans.arn}/*"
      }
    ]
  })
}

# ─── IAM: CI/CD uploader (S3 write only) ─────────────────────────────────────

resource "aws_iam_user" "cicd_uploader" {
  name = "snitch-cicd-uploader"
  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_access_key" "cicd_uploader" {
  user = aws_iam_user.cicd_uploader.name
}

resource "aws_iam_user_policy" "cicd_uploader" {
  name = "snitch-cicd-uploader-s3-put"
  user = aws_iam_user.cicd_uploader.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PutScanResults"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
        ]
        Resource = "${aws_s3_bucket.cicd_scans.arn}/*"
      }
    ]
  })
}
