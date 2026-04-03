"""
Response Body Scanner
=====================
Detects sensitive data exposure in API responses:
- Email addresses
- API keys / tokens
- Passwords / secrets
- Credit card numbers
- Private IPs
- Stack traces / verbose error messages
"""

import re
from typing import List

import httpx

from app.models.schemas import SecurityIssue, Severity
from app.scanners.base_scanner import BaseScanner


# ── Sensitive data patterns ────────────────────────────────────────────────────
PATTERNS = {
    "email": (
        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'),
        Severity.MEDIUM,
        "Email Address Exposure",
        "CWE-200",
    ),
    "aws_key": (
        re.compile(r'\b(AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}\b'),
        Severity.CRITICAL,
        "AWS Access Key ID Exposed",
        "CWE-312",
    ),
    "aws_secret": (
        re.compile(r'(?i)(aws.{0,20}secret.{0,20}[=:\s]["\']?)([A-Za-z0-9/+=]{40})'),
        Severity.CRITICAL,
        "AWS Secret Key Exposed",
        "CWE-312",
    ),
    "private_key": (
        re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
        Severity.CRITICAL,
        "Private Key Material Exposed",
        "CWE-312",
    ),
    "jwt_token": (
        re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        Severity.HIGH,
        "JWT Token in Response Body",
        "CWE-200",
    ),
    "generic_secret": (
        re.compile(r'(?i)(secret|password|passwd|api_key|apikey|token|private_key)\s*[=:]\s*["\']?[A-Za-z0-9!@#$%^&*]{8,}'),
        Severity.HIGH,
        "Secret/Password Pattern in Response",
        "CWE-312",
    ),
    "credit_card": (
        re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        Severity.CRITICAL,
        "Credit Card Number Exposed",
        "CWE-200",
    ),
    "private_ip": (
        re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'),
        Severity.LOW,
        "Internal/Private IP Address Disclosed",
        "CWE-200",
    ),
    "ssn": (
        re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        Severity.CRITICAL,
        "Social Security Number (SSN) Pattern Detected",
        "CWE-200",
    ),
    "bearer_token": (
        re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*'),
        Severity.HIGH,
        "Bearer Token Exposed in Response",
        "CWE-200",
    ),
}

# Stack trace indicators
STACK_TRACE_PATTERNS = [
    re.compile(r'Traceback \(most recent call last\)', re.IGNORECASE),
    re.compile(r'at [A-Za-z]+\.[A-Za-z]+\(.*\.java:\d+\)'),
    re.compile(r'System\.Exception|NullReferenceException|StackOverflowException', re.IGNORECASE),
    re.compile(r'Fatal error.*on line \d+', re.IGNORECASE),
    re.compile(r'SQL syntax.*MySQL|ORA-\d{5}|pg_query\(\)', re.IGNORECASE),
    re.compile(r'Exception in thread "main"', re.IGNORECASE),
]


class ResponseScanner(BaseScanner):

    async def scan(self, url: str, response: httpx.Response) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []

        # Only scan text-based responses
        content_type = response.headers.get("content-type", "")
        if not any(t in content_type for t in ("json", "text", "xml", "html")):
            return issues

        body = response.text

        # ── Check 1: Sensitive data patterns ─────────────────────────────────
        for pattern_name, (pattern, severity, title, cwe) in PATTERNS.items():
            match = pattern.search(body)
            if match:
                # Mask sensitive data in evidence
                found_text = match.group(0)
                masked = self._mask_value(found_text)
                issues.append(SecurityIssue(
                    id=f"RESPONSE-{len(issues)+1:03d}",
                    title=title,
                    description=(
                        f"The response body contains what appears to be a {title.lower()}. "
                        "Exposing sensitive data in API responses is a critical security risk."
                    ),
                    severity=severity,
                    category="Sensitive Data Exposure",
                    evidence=f"Pattern '{pattern_name}' matched: {masked}",
                    recommendation=(
                        "Remove sensitive data from API responses. "
                        "Use field filtering, response whitelisting, and data masking."
                    ),
                    cwe_id=cwe,
                    owasp_ref="A02:2021 – Cryptographic Failures",
                ))

        # ── Check 2: Stack trace / verbose errors ─────────────────────────────
        for pattern in STACK_TRACE_PATTERNS:
            if pattern.search(body):
                issues.append(SecurityIssue(
                    id="RESPONSE-TRACE",
                    title="Stack Trace or Verbose Error in Response",
                    description=(
                        "The response contains a stack trace or detailed error message. "
                        "This reveals internal implementation details and file paths."
                    ),
                    severity=Severity.MEDIUM,
                    category="Sensitive Data Exposure",
                    evidence="Stack trace pattern detected in response body",
                    recommendation=(
                        "Disable debug mode in production. "
                        "Return generic error messages to clients; log details server-side only."
                    ),
                    cwe_id="CWE-209",
                    owasp_ref="A05:2021 – Security Misconfiguration",
                ))
                break  # Only report once

        # ── Check 3: Large response body (potential data dump) ─────────────────
        if len(body) > 100_000:  # 100KB+
            issues.append(SecurityIssue(
                id="RESPONSE-LARGE",
                title="Unusually Large API Response Body",
                description=(
                    f"The response body is {len(body):,} bytes. "
                    "Large responses may indicate mass data exposure without pagination."
                ),
                severity=Severity.LOW,
                category="Sensitive Data Exposure",
                evidence=f"Response size: {len(body):,} bytes",
                recommendation="Implement pagination, field selection, and response size limits.",
                cwe_id="CWE-400",
                owasp_ref="A01:2021 – Broken Access Control",
            ))

        return issues

    @staticmethod
    def _mask_value(value: str) -> str:
        """Mask sensitive values for safe evidence logging."""
        if len(value) <= 8:
            return "***"
        return value[:4] + "***" + value[-4:]
