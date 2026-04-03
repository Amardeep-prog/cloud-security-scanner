"""
Report Routes
=============
GET /api/v1/report/{scan_id}  — Fetch individual report
GET /api/v1/history           — Paginated scan history
DELETE /api/v1/report/{scan_id} — Delete a report
"""

from fastapi import APIRouter, Depends, Request, Query, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.controllers.report_controller import ReportController
from app.models.schemas import ScanReport, HistoryResponse
from app.config import settings

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


def get_report_controller() -> ReportController:
    return ReportController()


@router.get(
    "/report/{scan_id}",
    response_model=ScanReport,
    summary="Fetch a scan report by ID",
)
@limiter.limit(settings.RATE_LIMIT_REPORT)
async def get_report(
    request: Request,
    scan_id: str,
    include_presigned: bool = Query(default=True, description="Include pre-signed S3 download URL"),
    controller: ReportController = Depends(get_report_controller),
) -> ScanReport:
    return await controller.get_report(scan_id, include_presigned)


@router.get(
    "/history",
    response_model=HistoryResponse,
    summary="Retrieve paginated scan history",
)
@limiter.limit(settings.RATE_LIMIT_REPORT)
async def get_history(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    tag: str = Query(default=None, description="Filter by tag"),
    controller: ReportController = Depends(get_report_controller),
) -> HistoryResponse:
    return await controller.get_history(page, page_size, tag)


@router.delete(
    "/report/{scan_id}",
    summary="Delete a scan report",
    status_code=204,
)
async def delete_report(
    scan_id: str,
    controller: ReportController = Depends(get_report_controller),
):
    await controller.delete_report(scan_id)
