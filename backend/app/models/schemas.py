"""
Pydantic Models — Request / Response Schemas
============================================
Strict input validation and structured output types.
"""
from __future__ import annotations
import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator, model_validator

# ─── Enums ───────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"

class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"

# ─── Request Models ──────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """Single URL scan request."""
    url: str = Field(..., description="Target API endpoint URL", example="https://api.example.com/v1/users")
    tags: Optional[List[str]] = Field(default=None, description="Optional labels for this scan")
    include_headers: bool = Field(default=True, description="Include security header analysis")
    include_cors: bool = Field(default=True, description="Include CORS misconfiguration check")
    include_response: bool = Field(default=True, description="Include response body analysis")
    timeout: Optional[int] = Field(default=None, ge=1, le=60, description="Override default timeout")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http or https scheme")
        if not parsed.netloc:
            raise ValueError("URL must have a valid hostname")
        blocked_patterns = [
            r"^localhost$", r"^127\.", r"^10\.", r"^172\.(1[6-9]|2\d|3[01])\.",
            r"^192\.168\.", r"^0\.0\.0\.0$", r"^::1$",
        ]
        hostname = parsed.hostname or ""
        for pattern in blocked_patterns:
            if re.match(pattern, hostname):
                raise ValueError(f"Scanning internal/private addresses is not allowed: {hostname}")
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v):
        if v and len(v) > 10:
            raise ValueError("Maximum 10 tags allowed")
        return v

class BulkScanRequest(BaseModel):
    """Multiple URL scan request."""
    urls: List[str] = Field(..., min_length=1, max_length=20, description="List of URLs to scan")
    tags: Optional[List[str]] = None
    parallel: bool = Field(default=True, description="Scan URLs concurrently")

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, urls: List[str]) -> List[str]:
        validated = []
        for url in urls:
            req = ScanRequest(url=url)
            validated.append(req.url)
        seen = set()
        deduped = []
        for u in validated:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped

# ─── Finding / Issue Models ───────────────────────────────────────────────────

class SecurityIssue(BaseModel):
    """A single detected security issue."""
    id: str = Field(..., description="Unique issue identifier, e.g. SEC-001")
    title: str
    description: str
    severity: Severity
    category: str = Field(..., description="e.g. 'Transport Security', 'CORS', 'Headers'")
    evidence: Optional[str] = Field(default=None, description="Raw evidence from the response")
    recommendation: str
    cwe_id: Optional[str] = Field(default=None, description="CWE reference, e.g. CWE-319")
    owasp_ref: Optional[str] = Field(default=None, description="OWASP Top 10 reference")

class ScanScore(BaseModel):
    """Numeric risk score for the scan."""
    total: float = Field(..., ge=0, le=100, description="Overall risk score (0=safe, 100=critical)")
    grade: str = Field(..., description="Letter grade: A+, A, B, C, D, F")
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

# ─── Report Model ─────────────────────────────────────────────────────────────

class ScanReport(BaseModel):
    """Complete scan report returned to the client."""
    scan_id: str
    url: str
    status: ScanStatus
    timestamp: datetime
    duration_ms: Optional[float] = None
    cloud: Optional[Dict] = None

    # HTTP metadata
    status_code: Optional[int] = None
    redirect_chain: List[str] = []
    final_url: Optional[str] = None
    server: Optional[str] = None
    tls_version: Optional[str] = None

    # Findings
    issues: List[SecurityIssue] = []
    score: Optional[ScanScore] = None
    tags: Optional[List[str]] = None

    # ✅ FIX: added missing subdomains field (was causing "ScanReport has no field subdomains" error)
    subdomains: List[str] = Field(default_factory=list, description="Discovered subdomains")

    # Storage
    s3_key: Optional[str] = None
    presigned_url: Optional[str] = None

    # Error info
    error: Optional[str] = None

# ─── Bulk / History / Health Models ──────────────────────────────────────────

class BulkScanReport(BaseModel):
    """Aggregated report for a bulk scan."""
    bulk_scan_id: str
    requested_at: datetime
    completed_at: Optional[datetime] = None
    total_urls: int
    completed: int = 0
    failed: int = 0
    reports: List[ScanReport] = []
    aggregate_score: Optional[float] = None

class ScanHistoryEntry(BaseModel):
    """Lightweight entry stored in DynamoDB for history."""
    scan_id: str
    url: str
    timestamp: datetime
    status: ScanStatus
    score: Optional[float] = None
    grade: Optional[str] = None
    issue_count: int = 0
    critical_count: int = 0
    s3_key: Optional[str] = None
    tags: Optional[List[str]] = None

class HistoryResponse(BaseModel):
    """Paginated history response."""
    items: List[ScanHistoryEntry]
    total: int
    page: int
    page_size: int
    has_more: bool

class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    aws_s3: str
    aws_dynamodb: str
    aws_cloudwatch: str
    uptime_seconds: float