"""
Scan Routes
===========
POST /api/v1/scan        — Single URL scan
POST /api/v1/bulk-scan   — Multiple URL scan
"""

from fastapi import APIRouter, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.controllers.scan_controller import ScanController
from app.models.schemas import ScanRequest, BulkScanRequest, ScanReport, BulkScanReport
from app.config import settings

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


def get_scan_controller() -> ScanController:
    return ScanController()


@router.post(
    "/scan",
    response_model=ScanReport,
    summary="Scan a single API endpoint",
    description="Perform a comprehensive security scan on a single URL.",
)
@limiter.limit(settings.RATE_LIMIT_SCAN)
async def scan_single(
    request: Request,
    body: ScanRequest,
    controller: ScanController = Depends(get_scan_controller),
) -> ScanReport:
    return await controller.scan_single(body)


@router.post(
    "/bulk-scan",
    response_model=BulkScanReport,
    summary="Scan multiple API endpoints",
    description="Perform concurrent security scans on up to 20 URLs.",
)
@limiter.limit(settings.RATE_LIMIT_BULK)
async def scan_bulk(
    request: Request,
    body: BulkScanRequest,
    controller: ScanController = Depends(get_scan_controller),
) -> BulkScanReport:
    return await controller.scan_bulk(body)
