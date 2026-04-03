"""
Scan Controller
===============
High-level orchestration:
Input → Scan → Store → Alert → Response
"""

import asyncio
import time
import uuid
from datetime import datetime, timezone

from app.models.schemas import (
    BulkScanReport, BulkScanRequest, ScanReport, ScanRequest, ScanStatus,
)
from app.services.scan_service import ScanService
from app.services.report_service import ReportService
from app.services.alert_service import AlertService
from app.utils.logger import get_logger
from app.config import settings

logger = get_logger(__name__)


class ScanController:
    def __init__(self):
        self.scan_service = ScanService()
        self.report_service = ReportService()
        self.alert_service = AlertService()

    # =========================
    # SINGLE SCAN
    # =========================
    async def scan_single(self, body: ScanRequest) -> ScanReport:
        scan_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        logger.info(f"[{scan_id}] Starting scan → {body.url}")

        # ✅ Basic validation
        if not body.url.startswith(("http://", "https://")):
            return ScanReport(
                scan_id=scan_id,
                url=body.url,
                status=ScanStatus.FAILED,
                error="Invalid URL format. Must start with http:// or https://",
                timestamp=datetime.now(timezone.utc),
            )

        # 🔁 Retry mechanism
        retries = settings.SCAN_RETRIES or 2
        report = None

        for attempt in range(retries + 1):
            try:
                report = await asyncio.wait_for(
                    self.scan_service.run_scan(
                        scan_id=scan_id,
                        url=body.url,
                        options=body,
                    ),
                    timeout=settings.SCAN_TIMEOUT_SECONDS + 5,
                )
                break
            except asyncio.TimeoutError:
                logger.warning(f"[{scan_id}] Timeout (attempt {attempt + 1})")
            except Exception as e:
                logger.error(f"[{scan_id}] Error (attempt {attempt + 1}): {e}")

        # ❌ All retries failed
        if not report:
            report = ScanReport(
                scan_id=scan_id,
                url=body.url,
                status=ScanStatus.FAILED,
                error="Scan failed after retries",
                timestamp=datetime.now(timezone.utc),
            )
        else:
            if not report.status:
                report.status = ScanStatus.COMPLETED

        if report and report.status == ScanStatus.RUNNING:
             report.status = ScanStatus.COMPLETED


        # 💾 Save report
        await self.report_service.save_report(report)

        # 🚨 Alert logic
        if report.score and report.score.critical_count >= settings.ALERT_CRITICAL_THRESHOLD:
            await self.alert_service.send_alert(report)

        duration = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(f"[{scan_id}] Scan complete in {duration}ms | Score={getattr(report.score, 'total', 'N/A')}")

        return report

    # =========================
    # BULK SCAN
    # =========================
    async def scan_bulk(self, body: BulkScanRequest) -> BulkScanReport:
        bulk_id = str(uuid.uuid4())
        logger.info(f"[{bulk_id}] Bulk scan started — {len(body.urls)} URLs")

        bulk_report = BulkScanReport(
            bulk_scan_id=bulk_id,
            requested_at=datetime.now(timezone.utc),
            total_urls=len(body.urls),
            completed=0,
            failed=0,
            reports=[],
        )

        semaphore = asyncio.Semaphore(settings.ASYNC_SCAN_CONCURRENCY)

        async def _safe_scan(url: str):
            async with semaphore:
                try:
                    scan_id = str(uuid.uuid4())

                    return await asyncio.wait_for(
                        self.scan_service.run_scan(
                            scan_id=scan_id,
                            url=url,
                            options=ScanRequest(url=url, tags=body.tags),
                        ),
                        timeout=settings.SCAN_TIMEOUT_SECONDS + 5,
                    )

                except Exception as e:
                    logger.error(f"[{bulk_id}] Failed scan for {url}: {e}")
                    return e

        # 🚀 Parallel or Sequential
        if body.parallel:
            results = await asyncio.gather(
                *[_safe_scan(url) for url in body.urls],
                return_exceptions=True,
            )
        else:
            results = []
            for url in body.urls:
                results.append(await _safe_scan(url))

        # 📊 Aggregate Results
        scores = []

        for result in results:
            if isinstance(result, Exception):
                bulk_report.failed += 1
                continue

            bulk_report.reports.append(result)
            bulk_report.completed += 1

            await self.report_service.save_report(result)

            if result.score:
                scores.append(result.score.total)

            # 🚨 Alert per result
            if result.score and result.score.critical_count >= settings.ALERT_CRITICAL_THRESHOLD:
                await self.alert_service.send_alert(result)

        # 📈 Aggregate score
        if scores:
            bulk_report.aggregate_score = round(sum(scores) / len(scores), 2)

        bulk_report.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"[{bulk_id}] Bulk done → {bulk_report.completed} success / {bulk_report.failed} failed"
        )

        return bulk_report