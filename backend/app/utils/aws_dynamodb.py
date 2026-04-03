"""
AWS DynamoDB Client
===================
Handles scan history storage using DynamoDB.
Table schema:
  PK: scan_id (String)
  GSI: timestamp-index on timestamp
Falls back gracefully if credentials are unavailable (dev environments).
"""
from decimal import Decimal
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError, NoCredentialsError

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class DynamoDBClient:
    """Wrapper around DynamoDB for scan history persistence."""

    def __init__(self):
        # ✅ FIX: added _enabled flag — all methods check this before calling AWS.
        #         Previously, missing credentials caused NoCredentialsError to
        #         propagate out of every method and crash the scan pipeline.
        self._enabled = False
        self._table = None

        kwargs = {"region_name": settings.AWS_REGION}
        if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY

        try:
            dynamodb = boto3.resource("dynamodb", **kwargs)
            self._table = dynamodb.Table(settings.DYNAMODB_TABLE_NAME)
            # Probe credentials early
            self._table.load()
            self._enabled = True
        except NoCredentialsError as exc:
            logger.warning(f"DynamoDB init failed (degraded mode): {exc}")
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code == "ResourceNotFoundException":
                logger.warning(f"DynamoDB table '{settings.DYNAMODB_TABLE_NAME}' not found (degraded mode)")
            else:
                logger.warning(f"DynamoDB init failed (degraded mode): {exc}")
        except Exception as exc:
            logger.warning(f"DynamoDB init failed (degraded mode): {exc}")

    # ── Write ─────────────────────────────────────────────────────────────────

    def put_item(self, item: Dict[str, Any]) -> None:
        """Write a scan history record. Serializes datetimes to ISO strings."""
        if not self._enabled:
            logger.warning("DynamoDB unavailable — skipping put_item")
            return

        serialized = self._serialize(item)
        try:
            self._table.put_item(Item=serialized)
        except ClientError as exc:
            logger.error(f"DynamoDB put_item failed: {exc}")
            raise

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_item(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if not self._enabled:
            logger.warning("DynamoDB unavailable — skipping get_item")
            return None

        try:
            resp = self._table.get_item(Key={"scan_id": scan_id})
            item = resp.get("Item")
            return self._deserialize(item) if item else None
        except ClientError as exc:
            logger.error(f"DynamoDB get_item failed: {exc}")
            raise

    def list_items(
        self,
        page: int = 1,
        page_size: int = 20,
        tag_filter: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Scan the table with optional tag filtering.
        Returns (items_page, total_count).
        Note: For production, replace scan() with a GSI query for efficiency.
        """
        if not self._enabled:
            logger.warning("DynamoDB unavailable — returning empty list")
            return [], 0

        try:
            filter_expr = None
            if tag_filter:
                filter_expr = Attr("tags").contains(tag_filter)

            kwargs: Dict[str, Any] = {}
            if filter_expr:
                kwargs["FilterExpression"] = filter_expr

            all_items = []
            resp = self._table.scan(**kwargs)
            all_items.extend(resp.get("Items", []))

            while "LastEvaluatedKey" in resp:
                resp = self._table.scan(
                    ExclusiveStartKey=resp["LastEvaluatedKey"],
                    **kwargs,
                )
                all_items.extend(resp.get("Items", []))

            all_items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

            total = len(all_items)
            start = (page - 1) * page_size
            end = start + page_size
            page_items = [self._deserialize(i) for i in all_items[start:end]]
            return page_items, total

        except ClientError as exc:
            logger.error(f"DynamoDB list_items failed: {exc}")
            raise

    # ── Delete ────────────────────────────────────────────────────────────────

    def delete_item(self, scan_id: str) -> None:
        if not self._enabled:
            logger.warning("DynamoDB unavailable — skipping delete_item")
            return

        try:
            self._table.delete_item(Key={"scan_id": scan_id})
        except ClientError as exc:
            logger.error(f"DynamoDB delete_item failed: {exc}")
            raise

    # ── Health check ──────────────────────────────────────────────────────────

    def check_table(self) -> None:
        if not self._enabled:
            raise RuntimeError("DynamoDB client not initialized (degraded mode)")
        self._table.load()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _serialize(item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Python types to DynamoDB-safe types."""
        result = {}
        for k, v in item.items():
            if v is None:
                continue  # DynamoDB doesn't support None; skip nulls
            elif isinstance(v, datetime):
                result[k] = v.isoformat()
            elif isinstance(v, float):
                result[k] = Decimal(str(v))
            else:
                result[k] = v
        return result

    @staticmethod
    def _deserialize(item: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DynamoDB types back to Python types."""
        result = {}
        for k, v in item.items():
            if isinstance(v, Decimal):
                result[k] = float(v)
            else:
                result[k] = v
        return result