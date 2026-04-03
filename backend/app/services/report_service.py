"""
Report Service
==============
Handles storage + retrieval of scan reports.
"""

import asyncio
from typing import Optional

from app.models.schemas import (
    HistoryResponse, ScanHistoryEntry, ScanReport
)
from app.utils.aws_s3 import S3Client
from app.utils.aws_dynamodb import DynamoDBClient
from app.utils.aws_cloudwatch import CloudWatchLogger
from app.utils.logger import get_logger
from app.config import settings

logger = get_logger(__name__)


class ReportService:
    def __init__(self):
        self.s3 = S3Client()
        self.dynamo = DynamoDBClient()
        self.cw = CloudWatchLogger()

    # =========================
    # SAVE REPORT
    # =========================
    async def save_report(self, report: ScanReport) -> None:
        s3_key = f"{settings.S3_REPORT_PREFIX}{report.scan_id}.json"

        # Prepare JSON once
        report_json = report.model_dump_json(indent=2)

        # ── S3 Upload (NON-BLOCKING) ──
        try:
            await asyncio.to_thread(
                self.s3.put_object,
                key=s3_key,
                body=report_json.encode("utf-8"),
                content_type="application/json",
                metadata={
                    "scan-id": report.scan_id,
                    "url": (report.url or "")[:512],
                    "grade": getattr(report.score, "grade", "N/A"),
                },
            )

            report.s3_key = s3_key
            logger.info(f"[{report.scan_id}] S3 saved → {s3_key}")

        except Exception as exc:
            logger.error(f"[{report.scan_id}] S3 FAILED: {exc}", exc_info=True)
            self.cw.log_event("S3_UPLOAD_FAILED", {
                "scan_id": report.scan_id,
                "error": str(exc)
            })

        # ── DynamoDB Index (NON-BLOCKING) ──
        try:
            entry = ScanHistoryEntry(
                scan_id=report.scan_id,
                url=report.url,
                timestamp=report.timestamp,
                status=report.status,
                score=getattr(report.score, "total", None),
                grade=getattr(report.score, "grade", None),
                issue_count=len(report.issues or []),
                critical_count=getattr(report.score, "critical_count", 0),
                s3_key=s3_key,
                tags=report.tags,
            )

            await asyncio.to_thread(
                self.dynamo.put_item,
                entry.model_dump(mode="json")
            )

            logger.info(f"[{report.scan_id}] Dynamo indexed")

        except Exception as exc:
            logger.error(f"[{report.scan_id}] Dynamo FAILED: {exc}", exc_info=True)
            self.cw.log_event("DYNAMO_WRITE_FAILED", {
                "scan_id": report.scan_id,
                "error": str(exc)
            })

        # ── CloudWatch Event ──
        self.cw.log_event("SCAN_COMPLETED", {
            "scan_id": report.scan_id,
            "url": report.url,
            "score": str(getattr(report.score, "total", "N/A")),
            "grade": getattr(report.score, "grade", "N/A"),
            "issues": str(len(report.issues or [])),
        })

    # =========================
    # LOAD REPORT
    # =========================
    async def load_report(self, scan_id: str, include_presigned: bool = True) -> Optional[ScanReport]:
        try:
            item = await asyncio.to_thread(self.dynamo.get_item, scan_id)

            if not item or not item.get("s3_key"):
                return None

            raw = await asyncio.to_thread(self.s3.get_object, item["s3_key"])
            report = ScanReport.model_validate_json(raw)

            if include_presigned:
                report.presigned_url = await asyncio.to_thread(
                    self.s3.generate_presigned_url,
                    item["s3_key"],
                    settings.S3_PRESIGNED_URL_EXPIRY,
                )

            return report

        except Exception as exc:
            logger.error(f"Load failed [{scan_id}]: {exc}", exc_info=True)
            return None

    # =========================
    # HISTORY
    # =========================
    async def get_history(self, page: int, page_size: int, tag: Optional[str]) -> HistoryResponse:
        try:
            items, total = await asyncio.to_thread(
                self.dynamo.list_items,
                page=page,
                page_size=page_size,
                tag_filter=tag,
            )

            entries = [ScanHistoryEntry(**item) for item in items]

            return HistoryResponse(
                items=entries,
                total=total,
                page=page,
                page_size=page_size,
                has_more=(page * page_size) < total,
            )

        except Exception as exc:
            logger.error(f"History failed: {exc}", exc_info=True)
            return HistoryResponse(items=[], total=0, page=page, page_size=page_size, has_more=False)

    # =========================
    # DELETE
    # =========================
    async def delete_report(self, scan_id: str) -> bool:
        try:
            item = await asyncio.to_thread(self.dynamo.get_item, scan_id)

            if not item:
                return False

            if item.get("s3_key"):
                await asyncio.to_thread(self.s3.delete_object, item["s3_key"])

            await asyncio.to_thread(self.dynamo.delete_item, scan_id)

            logger.info(f"Deleted report {scan_id}")
            return True

        except Exception as exc:
            logger.error(f"Delete failed [{scan_id}]: {exc}", exc_info=True)
            return False