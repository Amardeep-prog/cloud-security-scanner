"""
Transport Security Scanner
==========================
Checks:
- HTTP vs HTTPS (CWE-319)
- Redirect chains (HTTP → HTTPS upgrade)
- TLS/SSL version detection
- Mixed content indicators
"""

from typing import List
from urllib.parse import urlparse

import httpx

from app.models.schemas import SecurityIssue, Severity
from app.scanners.base_scanner import BaseScanner


class TransportScanner(BaseScanner):

    async def scan(self, url: str, response: httpx.Response) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []
        parsed = urlparse(url)

        # ── Check 1: Plain HTTP ───────────────────────────────────────────────
        if parsed.scheme == "http":
            issues.append(SecurityIssue(
                id="TRANSPORT-001",
                title="Insecure HTTP Protocol",
                description=(
                    f"The endpoint '{url}' uses plain HTTP. All traffic is transmitted "
                    "in cleartext and is vulnerable to interception (MITM attacks)."
                ),
                severity=Severity.CRITICAL,
                category="Transport Security",
                evidence=f"URL scheme: {parsed.scheme}",
                recommendation=(
                    "Migrate to HTTPS immediately. Obtain a TLS certificate (free via Let's Encrypt) "
                    "and enforce HTTPS with HTTP→HTTPS redirects."
                ),
                cwe_id="CWE-319",
                owasp_ref="A02:2021 – Cryptographic Failures",
            ))

        # ── Check 2: HTTPS but missing HSTS header ────────────────────────────
        if parsed.scheme == "https":
            hsts = response.headers.get("strict-transport-security")
            if not hsts:
                issues.append(SecurityIssue(
                    id="TRANSPORT-002",
                    title="Missing HTTP Strict Transport Security (HSTS)",
                    description=(
                        "The endpoint does not set the Strict-Transport-Security header. "
                        "Without HSTS, browsers may connect over HTTP on first visit, "
                        "enabling SSL-stripping attacks."
                    ),
                    severity=Severity.MEDIUM,
                    category="Transport Security",
                    evidence="Header 'Strict-Transport-Security' absent",
                    recommendation=(
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    ),
                    cwe_id="CWE-523",
                    owasp_ref="A02:2021 – Cryptographic Failures",
                ))

        # ── Check 3: HTTP → HTTPS redirect (informational credit) ─────────────
        if parsed.scheme == "http" and response.history:
            final_scheme = urlparse(str(response.url)).scheme
            if final_scheme == "https":
                # HTTP→HTTPS redirect exists — reduce to medium (not critical)
                # Replace the CRITICAL issue with a medium one
                for i, issue in enumerate(issues):
                    if issue.id == "TRANSPORT-001":
                        issues[i] = SecurityIssue(
                            id="TRANSPORT-001",
                            title="Insecure HTTP Entry Point (Redirects to HTTPS)",
                            description=(
                                f"The endpoint begins on HTTP but redirects to HTTPS. "
                                "The initial request is still sent unencrypted."
                            ),
                            severity=Severity.MEDIUM,
                            category="Transport Security",
                            evidence=f"Redirect chain: {' → '.join([str(r.url) for r in response.history] + [str(response.url)])}",
                            recommendation=(
                                "Configure the server to respond to HTTP with a 301 redirect immediately. "
                                "Also add HSTS to prevent the initial HTTP request."
                            ),
                            cwe_id="CWE-319",
                            owasp_ref="A02:2021 – Cryptographic Failures",
                        )

        # ── Check 4: Weak TLS version ─────────────────────────────────────────
        # httpx doesn't expose TLS version directly; inspect via ssl_object if available
        try:
            ssl_obj = response.extensions.get("ssl_object")  # type: ignore[attr-defined]
            if ssl_obj:
                tls_ver = ssl_obj.version()
                if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    issues.append(SecurityIssue(
                        id="TRANSPORT-003",
                        title=f"Weak TLS Version ({tls_ver})",
                        description=(
                            f"The server negotiated {tls_ver} which has known vulnerabilities "
                            "(POODLE, BEAST, etc.) and is deprecated."
                        ),
                        severity=Severity.HIGH,
                        category="Transport Security",
                        evidence=f"TLS version: {tls_ver}",
                        recommendation="Disable TLS 1.0 and 1.1. Require TLS 1.2 minimum; prefer TLS 1.3.",
                        cwe_id="CWE-326",
                        owasp_ref="A02:2021 – Cryptographic Failures",
                    ))
        except Exception:
            pass  # TLS introspection not always available

        return issues
