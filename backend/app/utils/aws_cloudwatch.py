"""
AWS CloudWatch Logger
=====================
Sends structured log events to CloudWatch Logs.
Falls back gracefully if CloudWatch is unavailable (dev environments).
"""
import json
import time
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class CloudWatchLogger:
    """Structured event logger that ships to AWS CloudWatch Logs."""

    def __init__(self):
        self._client = None
        self._sequence_token: Optional[str] = None

        if not settings.CLOUDWATCH_ENABLED:
            logger.debug("CloudWatch disabled via settings.")
            return

        kwargs = {"region_name": settings.AWS_REGION}
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY

        try:
            self._client = boto3.client("logs", **kwargs)
            self._ensure_log_group_and_stream()
        except NoCredentialsError as exc:
            # ✅ FIX: NoCredentialsError was not explicitly caught here before —
            #         _ensure_log_group_and_stream() would raise it and bypass
            #         the outer except, crashing __init__ instead of degrading.
            logger.warning(f"CloudWatch init failed (degraded mode): {exc}")
            self._client = None
        except Exception as exc:
            logger.warning(f"CloudWatch init failed (degraded mode): {exc}")
            self._client = None

    def log_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Send a structured JSON event to CloudWatch.
        Silently degrades if CloudWatch is unavailable.
        """
        if not self._client:
            logger.debug(f"[CloudWatch DISABLED] {event_type}: {payload}")
            return

        message = json.dumps({
            "event": event_type,
            "app": settings.APP_NAME,
            "env": settings.ENVIRONMENT,
            **payload,
        })

        try:
            kwargs: Dict[str, Any] = {
                "logGroupName": settings.CLOUDWATCH_LOG_GROUP,
                "logStreamName": settings.CLOUDWATCH_LOG_STREAM,
                "logEvents": [{"timestamp": int(time.time() * 1000), "message": message}],
            }
            if self._sequence_token:
                kwargs["sequenceToken"] = self._sequence_token

            resp = self._client.put_log_events(**kwargs)
            self._sequence_token = resp.get("nextSequenceToken")

        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code == "InvalidSequenceTokenException":
                # Recover sequence token and retry once
                self._sequence_token = exc.response["Error"]["Message"].split()[-1]
                self.log_event(event_type, payload)
            else:
                logger.warning(f"CloudWatch put_log_events failed: {exc}")
        except NoCredentialsError as exc:
            # ✅ FIX: credentials can expire mid-session; degrade instead of crash
            logger.warning(f"CloudWatch credentials lost (degraded mode): {exc}")
            self._client = None
        except Exception as exc:
            logger.warning(f"CloudWatch logging degraded: {exc}")

    def check(self) -> None:
        """Health check: verify CloudWatch connectivity."""
        if not self._client:
            raise RuntimeError("CloudWatch client not initialized (degraded mode)")
        self._client.describe_log_groups(logGroupNamePrefix=settings.CLOUDWATCH_LOG_GROUP)

    # ── Private ───────────────────────────────────────────────────────────────

    def _ensure_log_group_and_stream(self) -> None:
        """Create log group and stream if they don't exist."""
        try:
            self._client.create_log_group(logGroupName=settings.CLOUDWATCH_LOG_GROUP)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                raise

        try:
            self._client.create_log_stream(
                logGroupName=settings.CLOUDWATCH_LOG_GROUP,
                logStreamName=settings.CLOUDWATCH_LOG_STREAM,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                raise