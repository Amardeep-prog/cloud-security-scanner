"""
Report Controller
=================
Handles report retrieval and history queries.
"""

from fastapi import HTTPException

from app.models.schemas import HistoryResponse, ScanReport
from app.services.report_service import ReportService
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ReportController:
    def __init__(self):
        self.report_service = ReportService()

    async def get_report(self, scan_id: str, include_presigned: bool = True) -> ScanReport:
        report = await self.report_service.load_report(scan_id, include_presigned)
        if not report:
            raise HTTPException(status_code=404, detail=f"Report not found: {scan_id}")
        return report

    async def get_history(self, page: int, page_size: int, tag: str | None) -> HistoryResponse:
        return await self.report_service.get_history(page, page_size, tag)

    async def delete_report(self, scan_id: str):
        deleted = await self.report_service.delete_report(scan_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Report not found: {scan_id}")
