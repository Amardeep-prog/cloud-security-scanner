"""
Health Check Routes
===================
GET /health         — Liveness probe
GET /health/ready   — Readiness probe (checks AWS services)
"""

import time
from fastapi import APIRouter
from app.models.schemas import HealthResponse
from app.utils.aws_s3 import S3Client
from app.utils.aws_dynamodb import DynamoDBClient
from app.utils.aws_cloudwatch import CloudWatchLogger
from app.config import settings

router = APIRouter()
_start_time = time.time()


@router.get("/", response_model=dict, summary="Liveness probe")
async def liveness():
    """Returns 200 if the application process is alive."""
    return {"status": "ok", "version": settings.APP_VERSION}


@router.get("/ready", response_model=HealthResponse, summary="Readiness probe")
async def readiness():
    """Checks connectivity to all downstream AWS services."""
    s3_status = "ok"
    dynamo_status = "ok"
    cw_status = "ok"

    try:
        S3Client().check_bucket()
    except Exception:
        s3_status = "degraded"

    try:
        DynamoDBClient().check_table()
    except Exception:
        dynamo_status = "degraded"

    try:
        CloudWatchLogger().check()
    except Exception:
        cw_status = "degraded"

    overall = "healthy" if all(s == "ok" for s in [s3_status, dynamo_status, cw_status]) else "degraded"

    return HealthResponse(
        status=overall,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        aws_s3=s3_status,
        aws_dynamodb=dynamo_status,
        aws_cloudwatch=cw_status,
        uptime_seconds=round(time.time() - _start_time, 2),
    )
