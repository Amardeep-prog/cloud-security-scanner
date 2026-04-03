"""
Authentication Scanner
======================
Detects authentication weaknesses:
- Endpoints returning sensitive data without authentication
- Missing WWW-Authenticate headers on 401
- JWT/token patterns in response
- Basic auth over HTTP
"""

import re
from typing import List

import httpx

from app.models.schemas import SecurityIssue, Severity
from app.scanners.base_scanner import BaseScanner
from app.config import settings


# Patterns that suggest a response should have required auth
SENSITIVE_PATH_PATTERNS = re.compile(
    r"/(admin|users|accounts|profile|dashboard|config|settings|internal|private|secret|token|auth)",
    re.IGNORECASE,
)

JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
)

# Common 200-response auth bypass signatures
AUTH_BYPASS_BODIES = [
    "admin", "root", "password", "secret", "token", "api_key", "apikey",
]


class AuthScanner(BaseScanner):

    async def scan(self, url: str, response: httpx.Response) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []
        status = response.status_code
        headers = {k.lower(): v for k, v in response.headers.items()}

        # ── Check 1: Sensitive path returns 200 without auth challenge ─────────
        if SENSITIVE_PATH_PATTERNS.search(url) and status == 200:
            issues.append(SecurityIssue(
                id="AUTH-001",
                title="Potentially Unauthenticated Access to Sensitive Endpoint",
                description=(
                    f"The path '{url}' matches a sensitive resource pattern and returned "
                    "HTTP 200 without an authentication challenge. This may indicate "
                    "a publicly accessible sensitive endpoint."
                ),
                severity=Severity.HIGH,
                category="Authentication",
                evidence=f"URL: {url} | Status: {status}",
                recommendation=(
                    "Verify this endpoint requires authentication. "
                    "Implement JWT/OAuth2 bearer token validation."
                ),
                cwe_id="CWE-306",
                owasp_ref="A07:2021 – Identification and Authentication Failures",
            ))

        # ── Check 2: 401 without WWW-Authenticate ─────────────────────────────
        if status == 401 and "www-authenticate" not in headers:
            issues.append(SecurityIssue(
                id="AUTH-002",
                title="401 Unauthorized Without WWW-Authenticate Header",
                description=(
                    "The endpoint returns 401 but omits the WWW-Authenticate header. "
                    "RFC 7235 requires this header to indicate the authentication scheme."
                ),
                severity=Severity.LOW,
                category="Authentication",
                evidence=f"Status: 401 | www-authenticate: absent",
                recommendation=(
                    "Include: WWW-Authenticate: Bearer realm='api', "
                    "or appropriate scheme."
                ),
                cwe_id="CWE-287",
                owasp_ref="A07:2021 – Identification and Authentication Failures",
            ))

        # ── Check 3: Basic auth over HTTP ─────────────────────────────────────
        www_auth = headers.get("www-authenticate", "")
        if "basic" in www_auth.lower() and url.startswith("http://"):
            issues.append(SecurityIssue(
                id="AUTH-003",
                title="HTTP Basic Authentication Over Plaintext HTTP",
                description=(
                    "The endpoint requests HTTP Basic Authentication over an insecure "
                    "HTTP connection. Credentials are Base64-encoded (not encrypted) and "
                    "can be trivially decoded by any network observer."
                ),
                severity=Severity.CRITICAL,
                category="Authentication",
                evidence=f"WWW-Authenticate: {www_auth} | Protocol: HTTP",
                recommendation="Migrate to HTTPS. Replace Basic Auth with OAuth2 / API keys.",
                cwe_id="CWE-523",
                owasp_ref="A02:2021 – Cryptographic Failures",
            ))

        # ── Check 4: Probe endpoint without auth → sensitive data leaked ──────
        await self._probe_no_auth(url, issues)

        return issues

    async def _probe_no_auth(self, url: str, issues: List[SecurityIssue]) -> None:
        """Re-probe the endpoint without any Authorization header to test open access."""
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(settings.SCAN_TIMEOUT_SECONDS),
                headers={"User-Agent": settings.SCAN_USER_AGENT},
                follow_redirects=True,
            ) as client:
                # Explicitly omit Authorization headers
                probe = await client.get(url)

            if probe.status_code == 200:
                body_snippet = probe.text[:1000].lower()
                # Check if body contains JWT tokens
                if JWT_PATTERN.search(probe.text):
                    issues.append(SecurityIssue(
                        id="AUTH-004",
                        title="JWT Token Exposed in Unauthenticated Response",
                        description=(
                            "A JWT token was found in the response body without requiring authentication. "
                            "This may expose credentials or session tokens."
                        ),
                        severity=Severity.CRITICAL,
                        category="Authentication",
                        evidence="JWT pattern detected in unauthenticated response",
                        recommendation="Never return tokens in responses. Require auth before serving any JWT.",
                        cwe_id="CWE-200",
                        owasp_ref="A02:2021 – Cryptographic Failures",
                    ))

        except Exception:
            pass
