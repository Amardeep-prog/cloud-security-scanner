#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# LocalStack Init Script
# Creates required AWS resources in LocalStack for local development.
# ──────────────────────────────────────────────────────────────────────────────

set -e
echo "🚀 Initializing LocalStack AWS resources..."

AWS="aws --endpoint-url=http://localhost:4566 --region us-east-1"

# ── S3 Bucket ─────────────────────────────────────────────────────────────────
echo "📦 Creating S3 bucket..."
$AWS s3 mb s3://cloud-security-scanner-reports || true
$AWS s3api put-bucket-versioning \
  --bucket cloud-security-scanner-reports \
  --versioning-configuration Status=Enabled || true

# ── DynamoDB Table ────────────────────────────────────────────────────────────
echo "🗃️  Creating DynamoDB table..."
$AWS dynamodb create-table \
  --table-name scan-history \
  --attribute-definitions \
    AttributeName=scan_id,AttributeType=S \
    AttributeName=timestamp,AttributeType=S \
  --key-schema AttributeName=scan_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --global-secondary-indexes '[
    {
      "IndexName": "timestamp-index",
      "KeySchema": [{"AttributeName":"timestamp","KeyType":"HASH"}],
      "Projection": {"ProjectionType":"ALL"}
    }
  ]' || true

# ── CloudWatch Log Group ──────────────────────────────────────────────────────
echo "📊 Creating CloudWatch log group..."
$AWS logs create-log-group \
  --log-group-name /cloud-security-scanner/app || true
$AWS logs create-log-stream \
  --log-group-name /cloud-security-scanner/app \
  --log-stream-name api-events || true

echo "✅ LocalStack init complete!"
