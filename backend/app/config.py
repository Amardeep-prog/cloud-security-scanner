"""
Configuration Management
========================
All settings loaded from environment variables with sensible defaults.
Never hardcode secrets — use .env files or AWS Secrets Manager.
"""
from functools import lru_cache
from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    # ── App ───────────────────────────────────────────────────────────────────
    APP_NAME: str = "Cloud Security Scanner"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    ENABLE_DOCS: bool = True
    SCAN_RETRIES: int = 2

    # ── Server ────────────────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]
    TRUSTED_HOSTS: List[str] = []

    # ── AWS ───────────────────────────────────────────────────────────────────
    # ✅ FIX: default region changed from us-east-1 → ap-south-1 to match .env
    AWS_REGION: str = "ap-south-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None

    # ── S3 ────────────────────────────────────────────────────────────────────
    # ✅ FIX: this is S3_BUCKET_NAME — .env was incorrectly using S3_BUCKET
    S3_BUCKET_NAME: str = "cloud-scanner-reports-123"
    S3_REPORT_PREFIX: str = "scan-reports/"
    S3_PRESIGNED_URL_EXPIRY: int = 3600

    # ── CloudWatch ────────────────────────────────────────────────────────────
    CLOUDWATCH_LOG_GROUP: str = "/cloud-security-scanner/app"
    CLOUDWATCH_LOG_STREAM: str = "api-events"
    CLOUDWATCH_ENABLED: bool = True

    # ── DynamoDB ──────────────────────────────────────────────────────────────
    DYNAMODB_TABLE_NAME: str = "scan-history"
    DYNAMODB_ENABLED: bool = True

    # ── Scanner ───────────────────────────────────────────────────────────────
    SCAN_TIMEOUT_SECONDS: int = 15
    SCAN_MAX_REDIRECTS: int = 5
    SCAN_USER_AGENT: str = "CloudSecurityScanner/1.0 (+https://github.com/yourorg/scanner)"
    BULK_SCAN_MAX_URLS: int = 20
    ASYNC_SCAN_CONCURRENCY: int = 5

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_SCAN: str = "10/minute"
    RATE_LIMIT_BULK: str = "3/minute"
    RATE_LIMIT_REPORT: str = "60/minute"

    # ── Security ──────────────────────────────────────────────────────────────
    API_KEY_HEADER: str = "X-API-Key"
    REQUIRE_API_KEY: bool = False
    API_KEYS: List[str] = []

    # ── Alerts ────────────────────────────────────────────────────────────────
    ALERT_CRITICAL_THRESHOLD: int = 1
    ALERT_SNS_TOPIC_ARN: Optional[str] = None

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}")
        return v

    @field_validator("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", mode="before")
    @classmethod
    def empty_string_to_none(cls, v):
        # ✅ FIX: .env sends empty string "" — boto3 needs None to fall back
        #         to IAM role / aws configure credentials, not an empty string.
        #         Without this, boto3 tries to auth with "" and fails.
        if v == "" or v is None:
            return None
        return v

    @field_validator("ALERT_SNS_TOPIC_ARN", mode="before")
    @classmethod
    def empty_sns_to_none(cls, v):
        # Same fix for SNS ARN — empty string should be None
        if v == "" or v is None:
            return None
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance — call this everywhere instead of importing Settings directly."""
    return Settings()


settings = get_settings()