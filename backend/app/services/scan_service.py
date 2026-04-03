"""
Scan Service - FINAL STABLE VERSION
"""
import time
import asyncio
from datetime import datetime, timezone
import httpx
from app.models.schemas import (
    ScanReport, ScanRequest, ScanScore, ScanStatus, SecurityIssue, Severity,
)
from app.scanners.transport_scanner import TransportScanner
from app.scanners.header_scanner import HeaderScanner
from app.scanners.cors_scanner import CORSScanner
from app.scanners.response_scanner import ResponseScanner
from app.scanners.auth_scanner import AuthScanner
from app.scanners.status_scanner import StatusScanner
from app.scanners.anomaly_detector import AnomalyDetector
from app.utils.logger import get_logger
from app.config import settings
from app.cloud_scanners.s3_advanced import detect_public_s3
from app.cloud_scanners.iam_scanner import detect_iam_exposure
from app.scanners.fuzz_scanner import fuzz_api
from app.recon.subdomain_scanner import find_subdomains
from app.cloud_scanners.cloud_intelligence import detect_cloud

logger = get_logger(__name__)

# =========================
# SCORE ENGINE
# =========================
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH:     10.0,
    Severity.MEDIUM:    4.0,
    Severity.LOW:       1.5,
    Severity.INFO:      0.0,
}

def _compute_score(issues: list[SecurityIssue]) -> ScanScore:
    raw   = sum(SEVERITY_WEIGHTS.get(i.severity, 0) for i in issues)
    total = min(round(raw, 2), 100.0)
    counts = {s: 0 for s in Severity}
    for issue in issues:
        counts[issue.severity] += 1
    if   total <= 5:  grade = "A+"
    elif total <= 15: grade = "A"
    elif total <= 30: grade = "B"
    elif total <= 50: grade = "C"
    elif total <= 70: grade = "D"
    else:             grade = "F"
    return ScanScore(
        total=total, grade=grade,
        critical_count=counts[Severity.CRITICAL],
        high_count=counts[Severity.HIGH],
        medium_count=counts[Severity.MEDIUM],
        low_count=counts[Severity.LOW],
        info_count=counts[Severity.INFO],
    )

# =========================
# ISSUE NORMALIZER
# =========================

# ✅ FIX: Maps advanced scanner source names to display categories
CATEGORY_MAP = {
    "S3":   "Cloud Storage",
    "IAM":  "Cloud Credentials",
    "Fuzz": "Injection",
}

def normalize_issue(issue_dict: dict, source: str = "Advanced") -> SecurityIssue | None:
    """
    Convert a raw dict from advanced scanners into a SecurityIssue.
    ✅ FIX: added `category` field — was missing, causing silent Pydantic
            validation failure so ALL advanced results were dropped.
    ✅ FIX: added `id` generation — was using issue text as ID which
            caused duplicate key warnings in React.
    """
    if not issue_dict or not isinstance(issue_dict, dict):
        return None
    try:
        title = issue_dict.get("issue") or issue_dict.get("title") or "Unknown Issue"
        severity_str = issue_dict.get("severity", "LOW").upper()

        # Guard against invalid severity values
        if severity_str not in Severity.__members__:
            severity_str = "LOW"

        return SecurityIssue(
            # ✅ FIX: generate a stable unique id
            id=f"{source}-{title[:20].replace(' ', '-').upper()}",
            title=title,
            description=issue_dict.get("description") or title,
            severity=Severity[severity_str],
            # ✅ FIX: category is required by schema — was never set before
            category=CATEGORY_MAP.get(source, "Advanced Scanner"),
            recommendation=issue_dict.get("recommendation", "Review and remediate this issue."),
            evidence=issue_dict.get("evidence"),
            cwe_id=issue_dict.get("cwe_id"),
            owasp_ref=issue_dict.get("owasp_ref"),
        )
    except Exception as e:
        logger.warning(f"normalize_issue failed for source={source}: {e} | data={issue_dict}")
        return None

# =========================
# MAIN SERVICE
# =========================
class ScanService:
    def __init__(self):
        self.scanners = [
            TransportScanner(),
            HeaderScanner(),
            CORSScanner(),
            AuthScanner(),
            ResponseScanner(),
            StatusScanner(),
            AnomalyDetector(),
        ]

    async def run_scan(self, scan_id: str, url: str, options: ScanRequest) -> ScanReport:
        start_ms = time.perf_counter()
        report = ScanReport(
            scan_id=scan_id,
            url=url,
            status=ScanStatus.RUNNING,
            timestamp=datetime.now(timezone.utc),
            tags=options.tags,
        )
        timeout = options.timeout or settings.SCAN_TIMEOUT_SECONDS

        # =========================
        # HTTP REQUEST
        # =========================
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                max_redirects=settings.SCAN_MAX_REDIRECTS,
                timeout=httpx.Timeout(timeout),
                headers={"User-Agent": settings.SCAN_USER_AGENT},
                verify=True,
            ) as client:
                http_response = await client.get(url)

            report.status_code  = http_response.status_code
            report.final_url    = str(http_response.url)
            report.server       = http_response.headers.get("server")
            report.redirect_chain = [str(r.url) for r in http_response.history]

        except Exception as exc:
            logger.error(f"[{scan_id}] Request failed: {exc}")
            report.status     = ScanStatus.FAILED
            report.error      = str(exc)
            report.duration_ms = round((time.perf_counter() - start_ms) * 1000, 2)
            return report

        # =========================
        # CORE SCANNERS (PARALLEL)
        # =========================
        enabled = []
        for scanner in self.scanners:
            name = scanner.__class__.__name__
            if name == "HeaderScanner"   and not options.include_headers:  continue
            if name == "CORSScanner"     and not options.include_cors:     continue
            if name == "ResponseScanner" and not options.include_response: continue
            enabled.append(scanner)

        tasks   = [s.scan(url=url, response=http_response) for s in enabled]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_issues: list[SecurityIssue] = []
        for scanner, result in zip(enabled, results):
            if isinstance(result, Exception):
                logger.error(f"[{scan_id}] {scanner.__class__.__name__} failed: {result}")
                continue
            if result:
                all_issues.extend(result)

        # =========================
        # ADVANCED SCANNERS
        # ✅ FIX: pass source name to normalize_issue so category is set correctly
        # =========================
        async def safe(name: str, coro):
            try:
                res = await asyncio.wait_for(coro, timeout=4)
                if res:
                    normalized = [normalize_issue(i, source=name) for i in res]
                    valid      = [i for i in normalized if i is not None]
                    all_issues.extend(valid)
                    logger.info(f"[{scan_id}] {name}: {len(valid)} issues added")
            except Exception as e:
                logger.warning(f"[{scan_id}] {name} failed: {e}")

        await safe("S3",   detect_public_s3(url))
        await safe("IAM",  detect_iam_exposure(http_response))
        await safe("Fuzz", fuzz_api(url))

        # =========================
        # SUBDOMAIN RECON
        # =========================
        try:
            report.subdomains = await find_subdomains(url) or []
            logger.info(f"[{scan_id}] Subdomains found: {len(report.subdomains)}")
        except Exception as e:
            logger.warning(f"[{scan_id}] Subdomain failed: {e}")
            report.subdomains = []

        # =========================
        # CLOUD DETECTION
        # =========================
        try:
            report.cloud = detect_cloud(url)
        except Exception:
            report.cloud = {"provider": "Unknown", "service": "Unknown"}

        # =========================
        # FINAL REPORT
        # =========================
        report.issues     = all_issues
        report.score      = _compute_score(all_issues)
        report.status     = ScanStatus.COMPLETED
        report.duration_ms = round((time.perf_counter() - start_ms) * 1000, 2)

        logger.info(
            f"[{scan_id}] Done — {len(all_issues)} issues | "
            f"score={report.score.total} | subdomains={len(report.subdomains)}"
        )
        return report