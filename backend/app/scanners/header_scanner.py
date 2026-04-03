"""
Security Headers Scanner
========================
Checks for the presence and configuration of critical security headers.
References: OWASP Secure Headers Project
"""

from typing import List, Optional
import httpx

from app.models.schemas import SecurityIssue, Severity
from app.scanners.base_scanner import BaseScanner


# Each entry: (header_name, issue_id, title, severity, recommendation, cwe)
REQUIRED_HEADERS = [
    (
        "content-security-policy",
        "HEADER-001",
        "Missing Content-Security-Policy (CSP)",
        Severity.HIGH,
        (
            "Add a Content-Security-Policy header to restrict resource loading. "
            "Start with: Content-Security-Policy: default-src 'self'"
        ),
        "CWE-693",
        "A05:2021 – Security Misconfiguration",
    ),
    (
        "x-content-type-options",
        "HEADER-002",
        "Missing X-Content-Type-Options",
        Severity.MEDIUM,
        "Add: X-Content-Type-Options: nosniff to prevent MIME-type sniffing attacks.",
        "CWE-693",
        "A05:2021 – Security Misconfiguration",
    ),
    (
        "x-frame-options",
        "HEADER-003",
        "Missing X-Frame-Options",
        Severity.MEDIUM,
        (
            "Add: X-Frame-Options: DENY (or SAMEORIGIN) to prevent clickjacking. "
            "Note: CSP frame-ancestors supersedes this for modern browsers."
        ),
        "CWE-693",
        "A05:2021 – Security Misconfiguration",
    ),
    (
        "referrer-policy",
        "HEADER-004",
        "Missing Referrer-Policy",
        Severity.LOW,
        "Add: Referrer-Policy: strict-origin-when-cross-origin to control referrer leakage.",
        "CWE-200",
        "A01:2021 – Broken Access Control",
    ),
    (
        "permissions-policy",
        "HEADER-005",
        "Missing Permissions-Policy",
        Severity.LOW,
        "Add Permissions-Policy to restrict browser feature access (camera, geolocation, etc.).",
        "CWE-693",
        "A05:2021 – Security Misconfiguration",
    ),
]

# Dangerous values to detect in existing headers
DANGEROUS_CSP_VALUES = ["unsafe-inline", "unsafe-eval", "*"]


class HeaderScanner(BaseScanner):

    async def scan(self, url: str, response: httpx.Response) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []
        headers = {k.lower(): v for k, v in response.headers.items()}

        # ── Check 1: Missing required headers ────────────────────────────────
        for header_name, issue_id, title, severity, recommendation, cwe, owasp in REQUIRED_HEADERS:
            if header_name not in headers:
                issues.append(SecurityIssue(
                    id=issue_id,
                    title=title,
                    description=f"The response does not include the '{header_name}' security header.",
                    severity=severity,
                    category="Security Headers",
                    evidence=f"Header '{header_name}' not present in response",
                    recommendation=recommendation,
                    cwe_id=cwe,
                    owasp_ref=owasp,
                ))

        # ── Check 2: Weak/Misconfigured CSP ──────────────────────────────────
        csp_value = headers.get("content-security-policy", "")
        if csp_value:
            for dangerous in DANGEROUS_CSP_VALUES:
                if dangerous in csp_value:
                    issues.append(SecurityIssue(
                        id="HEADER-006",
                        title=f"Weak CSP: '{dangerous}' detected",
                        description=(
                            f"The Content-Security-Policy contains '{dangerous}', which "
                            "significantly weakens cross-site scripting (XSS) protections."
                        ),
                        severity=Severity.HIGH,
                        category="Security Headers",
                        evidence=f"CSP: {csp_value[:200]}",
                        recommendation=f"Remove '{dangerous}' from CSP. Use nonces or hashes for inline scripts.",
                        cwe_id="CWE-693",
                        owasp_ref="A05:2021 – Security Misconfiguration",
                    ))
                    break

        # ── Check 3: Server header leaking version info ───────────────────────
        server_header = headers.get("server", "")
        x_powered_by = headers.get("x-powered-by", "")

        if server_header and any(c.isdigit() for c in server_header):
            issues.append(SecurityIssue(
                id="HEADER-007",
                title="Server Version Disclosure via 'Server' Header",
                description=(
                    "The 'Server' header exposes the server software version, "
                    "helping attackers identify known CVEs."
                ),
                severity=Severity.LOW,
                category="Security Headers",
                evidence=f"Server: {server_header}",
                recommendation="Remove or obscure the Server header at the web server level.",
                cwe_id="CWE-200",
                owasp_ref="A05:2021 – Security Misconfiguration",
            ))

        if x_powered_by:
            issues.append(SecurityIssue(
                id="HEADER-008",
                title="Technology Stack Disclosure via 'X-Powered-By' Header",
                description=(
                    "The 'X-Powered-By' header reveals the backend framework/language, "
                    "aiding targeted attacks."
                ),
                severity=Severity.LOW,
                category="Security Headers",
                evidence=f"X-Powered-By: {x_powered_by}",
                recommendation="Remove the X-Powered-By header from all responses.",
                cwe_id="CWE-200",
                owasp_ref="A05:2021 – Security Misconfiguration",
            ))

        # ── Check 4: Cache-Control for sensitive API responses ─────────────────
        cache_control = headers.get("cache-control", "")
        if not cache_control or "no-store" not in cache_control.lower():
            issues.append(SecurityIssue(
                id="HEADER-009",
                title="Potentially Cacheable API Response",
                description=(
                    "The API response does not explicitly disable caching. "
                    "Sensitive data may be stored in browser or proxy caches."
                ),
                severity=Severity.LOW,
                category="Security Headers",
                evidence=f"Cache-Control: {cache_control or '(absent)'}",
                recommendation="Add: Cache-Control: no-store, no-cache, must-revalidate for API endpoints.",
                cwe_id="CWE-524",
                owasp_ref="A02:2021 – Cryptographic Failures",
            ))

        return issues
