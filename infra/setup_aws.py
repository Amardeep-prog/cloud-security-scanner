"""
AWS Infrastructure Setup Script
================================
Creates all required AWS resources for production deployment.
Run once during initial setup:
    python infra/setup_aws.py
"""

import boto3
import json
import sys


REGION = "us-east-1"
BUCKET_NAME = "cloud-security-scanner-reports"
TABLE_NAME = "scan-history"
LOG_GROUP = "/cloud-security-scanner/app"


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


def create_s3_bucket(s3, account_id):
    print(f"📦 Creating S3 bucket: {BUCKET_NAME}")
    try:
        if REGION == "us-east-1":
            s3.create_bucket(Bucket=BUCKET_NAME)
        else:
            s3.create_bucket(
                Bucket=BUCKET_NAME,
                CreateBucketConfiguration={"LocationConstraint": REGION},
            )
    except s3.exceptions.BucketAlreadyOwnedByYou:
        print("   Bucket already exists, skipping.")
        return

    # Enable versioning
    s3.put_bucket_versioning(
        Bucket=BUCKET_NAME,
        VersioningConfiguration={"Status": "Enabled"},
    )

    # Block all public access (critical security setting)
    s3.put_public_access_block(
        Bucket=BUCKET_NAME,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    # Enable server-side encryption
    s3.put_bucket_encryption(
        Bucket=BUCKET_NAME,
        ServerSideEncryptionConfiguration={
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }]
        },
    )

    # Lifecycle: auto-delete reports after 90 days
    s3.put_bucket_lifecycle_configuration(
        Bucket=BUCKET_NAME,
        LifecycleConfiguration={
            "Rules": [{
                "ID": "expire-reports",
                "Status": "Enabled",
                "Filter": {"Prefix": "scan-reports/"},
                "Expiration": {"Days": 90},
            }]
        },
    )
    print("   ✅ S3 bucket configured with encryption, public block, lifecycle.")


def create_dynamodb_table(dynamodb):
    print(f"🗃️  Creating DynamoDB table: {TABLE_NAME}")
    try:
        dynamodb.create_table(
            TableName=TABLE_NAME,
            AttributeDefinitions=[
                {"AttributeName": "scan_id", "AttributeType": "S"},
                {"AttributeName": "timestamp", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "scan_id", "KeyType": "HASH"},
            ],
            BillingMode="PAY_PER_REQUEST",
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "timestamp-index",
                    "KeySchema": [{"AttributeName": "timestamp", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            SSESpecification={"Enabled": True},  # Encryption at rest
            Tags=[
                {"Key": "Project", "Value": "CloudSecurityScanner"},
                {"Key": "Environment", "Value": "production"},
            ],
        )
        print("   ✅ DynamoDB table created.")
    except dynamodb.exceptions.ResourceInUseException:
        print("   Table already exists, skipping.")


def create_cloudwatch(logs):
    print(f"📊 Creating CloudWatch log group: {LOG_GROUP}")
    try:
        logs.create_log_group(logGroupName=LOG_GROUP)
        logs.put_retention_policy(
            logGroupName=LOG_GROUP,
            retentionInDays=30,
        )
        logs.create_log_stream(
            logGroupName=LOG_GROUP,
            logStreamName="api-events",
        )
        print("   ✅ CloudWatch log group created (30-day retention).")
    except logs.exceptions.ResourceAlreadyExistsException:
        print("   Log group already exists, skipping.")


def create_iam_policy(iam, account_id):
    """Create a least-privilege IAM policy for the scanner service."""
    print("🔐 Creating IAM policy (least privilege)...")
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S3ScanReports",
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:HeadBucket"],
                "Resource": [
                    f"arn:aws:s3:::{BUCKET_NAME}",
                    f"arn:aws:s3:::{BUCKET_NAME}/*",
                ],
            },
            {
                "Sid": "DynamoDBScanHistory",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:DeleteItem",
                    "dynamodb:Scan", "dynamodb:Query", "dynamodb:DescribeTable",
                ],
                "Resource": [
                    f"arn:aws:dynamodb:{REGION}:{account_id}:table/{TABLE_NAME}",
                    f"arn:aws:dynamodb:{REGION}:{account_id}:table/{TABLE_NAME}/index/*",
                ],
            },
            {
                "Sid": "CloudWatchLogs",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup", "logs:CreateLogStream",
                    "logs:PutLogEvents", "logs:DescribeLogGroups",
                ],
                "Resource": f"arn:aws:logs:{REGION}:{account_id}:log-group:{LOG_GROUP}:*",
            },
        ],
    }

    try:
        resp = iam.create_policy(
            PolicyName="CloudSecurityScannerPolicy",
            PolicyDocument=json.dumps(policy_document),
            Description="Least-privilege policy for Cloud Security Scanner service",
            Tags=[{"Key": "Project", "Value": "CloudSecurityScanner"}],
        )
        print(f"   ✅ IAM policy created: {resp['Policy']['Arn']}")
    except iam.exceptions.EntityAlreadyExistsException:
        print("   IAM policy already exists, skipping.")


def main():
    session = boto3.Session(region_name=REGION)
    account_id = get_account_id(session)
    print(f"\n🏗️  Setting up AWS resources in account {account_id}, region {REGION}\n")

    create_s3_bucket(session.client("s3"), account_id)
    create_dynamodb_table(session.client("dynamodb"))
    create_cloudwatch(session.client("logs"))
    create_iam_policy(session.client("iam"), account_id)

    print("\n✅ All AWS resources configured successfully!")
    print(f"   S3 Bucket:       {BUCKET_NAME}")
    print(f"   DynamoDB Table:  {TABLE_NAME}")
    print(f"   CloudWatch:      {LOG_GROUP}")


if __name__ == "__main__":
    main()
