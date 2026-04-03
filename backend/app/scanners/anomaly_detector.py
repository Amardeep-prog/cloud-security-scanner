"""
Anomaly Detector
================
Rule-based anomaly detection for API responses.
Detects unusual patterns that may indicate misconfigurations or attacks.
"""

import re
from typing import List
import httpx

from app.models.schemas import SecurityIssue, Severity
from app.scanners.base_scanner import BaseScanner
from app.config import settings


class AnomalyDetector(BaseScanner):

    async def scan(self, url: str, response: httpx.Response) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text[:50_000]  # Limit analysis to first 50KB

        # ── Check 1: Inconsistent Content-Type ───────────────────────────────
        content_type = headers.get("content-type", "")
        if content_type:
            is_json_ct = "json" in content_type
            looks_json = body.strip().startswith(("{", "["))
            is_html_ct = "html" in content_type
            looks_html = "<html" in body.lower() or "<!doctype" in body.lower()

            if is_json_ct and looks_html:
                issues.append(SecurityIssue(
                    id="ANOMALY-001",
                    title="Content-Type Mismatch: JSON declared but HTML returned",
                    description=(
                        "The response declares Content-Type: application/json "
                        "but the body appears to be HTML. This could indicate "
                        "a misconfiguration or reflected XSS opportunity."
                    ),
                    severity=Severity.MEDIUM,
                    category="Anomaly Detection",
                    evidence=f"Content-Type: {content_type} | Body starts with: {body[:50]}",
                    recommendation="Ensure Content-Type accurately reflects the response body format.",
                    cwe_id="CWE-116",
                    owasp_ref="A05:2021 – Security Misconfiguration",
                ))

        # ── Check 2: Debug mode indicators ───────────────────────────────────
        debug_patterns = [
            r'"debug"\s*:\s*true',
            r'"environment"\s*:\s*"(development|dev|local|test)"',
            r'"stack_trace"',
            r'"sql_query"',
            r'"internal_error"',
            r'X-Debug-Token',
            r'X-Symfony-Profiler',
        ]
        for pattern in debug_patterns:
            if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, str(headers), re.IGNORECASE):
                issues.append(SecurityIssue(
                    id="ANOMALY-002",
                    title="Debug Mode or Development Environment Detected",
                    description=(
                        "The response contains indicators of debug mode being enabled "
                        "or a development environment configuration. This exposes internal "
                        "application details."
                    ),
                    severity=Severity.HIGH,
                    category="Anomaly Detection",
                    evidence=f"Pattern matched: {pattern}",
                    recommendation=(
                        "Disable debug mode in production. "
                        "Use environment-specific configs and never expose debug endpoints publicly."
                    ),
                    cwe_id="CWE-489",
                    owasp_ref="A05:2021 – Security Misconfiguration",
                ))
                break

        # ── Check 3: Directory listing ────────────────────────────────────────
        if re.search(r'Index of /', body, re.IGNORECASE) and "<a href=" in body:
            issues.append(SecurityIssue(
                id="ANOMALY-003",
                title="Directory Listing Enabled",
                description=(
                    "The server appears to have directory listing enabled, "
                    "exposing the file structure of the web root."
                ),
                severity=Severity.HIGH,
                category="Anomaly Detection",
                evidence="'Index of /' pattern detected in response",
                recommendation=(
                    "Disable directory listing (e.g., 'Options -Indexes' in Apache, "
                    "'autoindex off' in Nginx)."
                ),
                cwe_id="CWE-548",
                owasp_ref="A05:2021 – Security Misconfiguration",
            ))

        # ── Check 4: Default/framework error pages ────────────────────────────
        framework_errors = [
            ("Django", r"Django\s+Version:|A server error occurred"),
            ("Laravel", r"Whoops,\s+looks like something went wrong|Laravel"),
            ("Rails", r"ActionController::RoutingError|Ruby on Rails"),
            ("Spring", r"Whitelabel Error Page|Spring Framework"),
            ("Express", r"Cannot (GET|POST|PUT|DELETE) /"),
            ("Flask", r"Traceback.*flask"),
        ]
        for framework, pattern in framework_errors:
            if re.search(pattern, body, re.IGNORECASE):
                issues.append(SecurityIssue(
                    id="ANOMALY-004",
                    title=f"Framework Default Error Page Exposed ({framework})",
                    description=(
                        f"A default {framework} error page was detected. "
                        "This reveals the backend technology stack and may expose "
                        "internal paths and error details."
                    ),
                    severity=Severity.MEDIUM,
                    category="Anomaly Detection",
                    evidence=f"Framework pattern matched: {framework}",
                    recommendation=(
                        "Implement custom error pages for all HTTP error codes. "
                        "Disable framework debug output in production."
                    ),
                    cwe_id="CWE-209",
                    owasp_ref="A05:2021 – Security Misconfiguration",
                ))
                break

        # ── Check 5: Suspicious response timing (basic fuzzing probe) ─────────
        await self._timing_probe(url, issues)

        return issues

    async def _timing_probe(self, url: str, issues: List[SecurityIssue]) -> None:
        """
        Basic timing anomaly: inject a sleep-based payload in query params
        to detect potential SQL injection (time-based blind).
        This is a non-destructive, read-only probe.
        """
        import time
        payloads = ["' OR SLEEP(2)--", "1; WAITFOR DELAY '0:0:2'--"]
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(5.0),
                headers={"User-Agent": settings.SCAN_USER_AGENT},
                follow_redirects=False,
            ) as client:
                for payload in payloads:
                    start = time.perf_counter()
                    try:
                        await client.get(url, params={"id": payload})
                        elapsed = time.perf_counter() - start
                        if elapsed >= 1.8:  # Suspicious if delayed ~2s
                            issues.append(SecurityIssue(
                                id="ANOMALY-005",
                                title="Possible Time-Based SQL Injection (Timing Anomaly)",
                                description=(
                                    f"A request with a SQL sleep payload caused a {elapsed:.1f}s delay, "
                                    "suggesting the application may be vulnerable to time-based blind SQL injection."
                                ),
                                severity=Severity.CRITICAL,
                                category="Anomaly Detection",
                                evidence=f"Payload: {payload!r} | Elapsed: {elapsed:.2f}s",
                                recommendation=(
                                    "Use parameterized queries / prepared statements. "
                                    "Implement input validation and WAF rules."
                                ),
                                cwe_id="CWE-89",
                                owasp_ref="A03:2021 – Injection",
                            ))
                            break
                    except Exception:
                        pass
        except Exception:
            pass
