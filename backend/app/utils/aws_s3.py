"""
AWS S3 Client
=============
Handles all S3 operations: put, get, delete, presigned URLs.
Uses boto3 with environment-based credentials or IAM roles.
Falls back gracefully if credentials are unavailable (dev environments).
"""
from typing import Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class S3Client:
    """Thin wrapper around boto3 S3 with project-specific helpers."""

    def __init__(self):
        # ✅ FIX: added _enabled flag — all methods check this before calling AWS.
        #         Previously, missing credentials caused an unhandled crash on
        #         every S3 operation instead of degrading gracefully.
        self._enabled = False
        self._s3 = None
        self._bucket = settings.S3_BUCKET_NAME

        kwargs = {"region_name": settings.AWS_REGION}
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY

        try:
            self._s3 = boto3.client("s3", **kwargs)
            # Probe credentials early so we fail fast here, not mid-scan
            self._s3.head_bucket(Bucket=self._bucket)
            self._enabled = True
        except NoCredentialsError as exc:
            logger.warning(f"S3 init failed (degraded mode): {exc}")
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code in ("403", "404", "NoSuchBucket"):
                # Bucket exists but access denied or not found — still mark enabled
                # so operations can fail with proper errors rather than silently skip
                self._enabled = True
            else:
                logger.warning(f"S3 init failed (degraded mode): {exc}")
        except Exception as exc:
            logger.warning(f"S3 init failed (degraded mode): {exc}")

    # ── Write ─────────────────────────────────────────────────────────────────

    def put_object(
        self,
        key: str,
        body: bytes,
        content_type: str = "application/json",
        metadata: Optional[dict] = None,
    ) -> None:
        """Upload bytes to S3 with server-side encryption."""
        if not self._enabled:
            logger.warning(f"S3 unavailable — skipping put_object for key '{key}'")
            return

        try:
            self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                ContentType=content_type,
                ServerSideEncryption="AES256",
                Metadata=metadata or {},
            )
        except ClientError as exc:
            logger.error(f"S3 put_object failed for key '{key}': {exc}")
            raise

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_object(self, key: str) -> str:
        """Download and return S3 object as a UTF-8 string."""
        if not self._enabled:
            logger.warning(f"S3 unavailable — skipping get_object for key '{key}'")
            return ""

        try:
            resp = self._s3.get_object(Bucket=self._bucket, Key=key)
            return resp["Body"].read().decode("utf-8")
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code == "NoSuchKey":
                raise FileNotFoundError(f"S3 key not found: {key}") from exc
            logger.error(f"S3 get_object failed for key '{key}': {exc}")
            raise

    # ── Delete ────────────────────────────────────────────────────────────────

    def delete_object(self, key: str) -> None:
        if not self._enabled:
            logger.warning(f"S3 unavailable — skipping delete_object for key '{key}'")
            return

        try:
            self._s3.delete_object(Bucket=self._bucket, Key=key)
        except ClientError as exc:
            logger.error(f"S3 delete_object failed for key '{key}': {exc}")
            raise

    # ── Presigned URL ─────────────────────────────────────────────────────────

    def generate_presigned_url(self, key: str, expiry: int = 3600) -> Optional[str]:
        """Generate a time-limited pre-signed URL for secure report download."""
        if not self._enabled:
            logger.warning("S3 unavailable — cannot generate presigned URL")
            return None

        try:
            return self._s3.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": self._bucket, "Key": key},
                ExpiresIn=expiry,
            )
        except (ClientError, NoCredentialsError) as exc:
            logger.error(f"Presigned URL generation failed: {exc}")
            return None

    # ── Health check ──────────────────────────────────────────────────────────

    def check_bucket(self) -> None:
        """Verify bucket exists and is accessible (used in health check)."""
        if not self._enabled:
            raise RuntimeError("S3 client not initialized (degraded mode)")
        self._s3.head_bucket(Bucket=self._bucket)