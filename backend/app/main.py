"""
Cloud Security Scanner - Main Application Entry Point
=====================================================
FastAPI-based API security scanning service with AWS integration.
Author: Cloud Security Scanner Team
"""

import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.routes import scan_routes, report_routes, health_routes
from app.utils.logger import get_logger
from app.utils.aws_cloudwatch import CloudWatchLogger
from app.config import settings

# ─── Logger ──────────────────────────────────────────────────────────────────
logger = get_logger(__name__)
cw_logger = CloudWatchLogger()

# ─── Rate Limiter ─────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    logger.info("🚀 Cloud Security Scanner starting up...")
    cw_logger.log_event("APP_STARTUP", {"version": settings.APP_VERSION})
    yield
    logger.info("🛑 Cloud Security Scanner shutting down...")
    cw_logger.log_event("APP_SHUTDOWN", {})


# ─── App Factory ──────────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title="Cloud Security Scanner",
        description=(
            "Production-grade API security scanning service. "
            "Detect vulnerabilities, misconfigurations, and security gaps in your APIs."
        ),
        version=settings.APP_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["*"],
    )

    if settings.TRUSTED_HOSTS:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.TRUSTED_HOSTS,
        )

    # ── Request ID + Timing Middleware ────────────────────────────────────────
    @app.middleware("http")
    async def request_middleware(request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()

        response = await call_next(request)

        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms}ms"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        logger.info(
            f"[{request_id}] {request.method} {request.url.path} "
            f"→ {response.status_code} ({duration_ms}ms)"
        )
        return response

    # ── Routes ────────────────────────────────────────────────────────────────
    app.include_router(health_routes.router, prefix="/health", tags=["Health"])
    app.include_router(scan_routes.router,   prefix="/api/v1", tags=["Scanning"])
    app.include_router(report_routes.router, prefix="/api/v1", tags=["Reports"])

    # ── Global Exception Handler ──────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        cw_logger.log_event("UNHANDLED_EXCEPTION", {"error": str(exc)})
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": getattr(request.state, "request_id", "unknown")},
        )

    return app


app = create_app()
