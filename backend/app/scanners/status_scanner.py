"""
Status Code Scanner
===================
Analyzes HTTP status codes for security-relevant patterns.
"""

from typing import List
import httpx

from app.models.schemas import SecurityIssue, Severity
from app.scanners.base_scanner import BaseScanner
from app.config import settings


class StatusScanner(BaseScanner):

    async def scan(self, url: str, response: httpx.Response) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []
        status = response.status_code

        # ── 500-range: Server errors revealing implementation ─────────────────
        if 500 <= status <= 599:
            issues.append(SecurityIssue(
                id="STATUS-001",
                title=f"Server Error ({status}) Returned",
                description=(
                    f"The endpoint returned HTTP {status}, indicating an unhandled server-side error. "
                    "Server errors can expose internal implementation details."
                ),
                severity=Severity.MEDIUM,
                category="Status Code",
                evidence=f"HTTP {status} {response.reason_phrase}",
                recommendation=(
                    "Implement global error handling. "
                    "Return generic 500 responses without stack traces to clients."
                ),
                cwe_id="CWE-209",
                owasp_ref="A05:2021 – Security Misconfiguration",
            ))

        # ── 403 vs 401: Authentication vs Authorization confusion ──────────────
        if status == 403:
            issues.append(SecurityIssue(
                id="STATUS-002",
                title="HTTP 403 Forbidden — Possible Access Control Issue",
                description=(
                    "HTTP 403 indicates the server understood the request but refused it. "
                    "Verify this is intentional and doesn't leak information about resource existence."
                ),
                severity=Severity.INFO,
                category="Status Code",
                evidence=f"HTTP 403 Forbidden",
                recommendation=(
                    "Return 404 instead of 403 for sensitive resources to avoid confirming existence. "
                    "Ensure access control checks are consistently applied."
                ),
                cwe_id="CWE-285",
                owasp_ref="A01:2021 – Broken Access Control",
            ))

        # ── 200 OK with empty body ────────────────────────────────────────────
        if status == 200 and len(response.text.strip()) == 0:
            issues.append(SecurityIssue(
                id="STATUS-003",
                title="HTTP 200 with Empty Response Body",
                description=(
                    "The endpoint returns 200 OK but no body. This may indicate "
                    "a misconfigured endpoint or accidental data stripping."
                ),
                severity=Severity.INFO,
                category="Status Code",
                evidence="Response body is empty with 200 status",
                recommendation="Verify this is intentional. APIs should return appropriate status codes.",
                cwe_id=None,
                owasp_ref=None,
            ))

        # ── TRACE method detection ────────────────────────────────────────────
        await self._check_trace_method(url, issues)

        # ── Redirect to different domain ──────────────────────────────────────
        if response.history:
            from urllib.parse import urlparse
            original_host = urlparse(url).hostname
            final_host = urlparse(str(response.url)).hostname
            if original_host != final_host:
                issues.append(SecurityIssue(
                    id="STATUS-004",
                    title="Cross-Domain Redirect Detected",
                    description=(
                        f"The request to '{url}' redirected to a different domain '{final_host}'. "
                        "Cross-domain redirects can be used in phishing or token-theft attacks."
                    ),
                    severity=Severity.MEDIUM,
                    category="Status Code",
                    evidence=f"Original: {original_host} → Final: {final_host}",
                    recommendation=(
                        "Validate redirect destinations. "
                        "Never redirect based on unvalidated user input (Open Redirect)."
                    ),
                    cwe_id="CWE-601",
                    owasp_ref="A01:2021 – Broken Access Control",
                ))

        return issues

    async def _check_trace_method(self, url: str, issues: List[SecurityIssue]) -> None:
        """Send an HTTP TRACE request to detect XST (Cross-Site Tracing) vulnerability."""
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(settings.SCAN_TIMEOUT_SECONDS),
                headers={"User-Agent": settings.SCAN_USER_AGENT},
            ) as client:
                trace_resp = await client.request("TRACE", url)

            if trace_resp.status_code in (200, 204) or "TRACE" in trace_resp.text.upper():
                issues.append(SecurityIssue(
                    id="STATUS-005",
                    title="HTTP TRACE Method Enabled (XST Vulnerability)",
                    description=(
                        "The server accepts HTTP TRACE requests, enabling Cross-Site Tracing (XST). "
                        "An attacker could use this to steal HttpOnly cookies."
                    ),
                    severity=Severity.HIGH,
                    category="Status Code",
                    evidence=f"TRACE method returned HTTP {trace_resp.status_code}",
                    recommendation=(
                        "Disable HTTP TRACE/TRACK methods at the web server level. "
                        "For Nginx: 'if ($request_method = TRACE) { return 405; }'"
                    ),
                    cwe_id="CWE-693",
                    owasp_ref="A05:2021 – Security Misconfiguration",
                ))
        except Exception:
            pass
