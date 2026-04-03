"""
CORS Misconfiguration Scanner
==============================
Checks for dangerous Cross-Origin Resource Sharing configurations.
Simulates cross-origin preflight requests to detect real CORS policy.
"""

from typing import List
import httpx

from app.models.schemas import SecurityIssue, Severity
from app.scanners.base_scanner import BaseScanner
from app.config import settings


class CORSScanner(BaseScanner):

    async def scan(self, url: str, response: httpx.Response) -> List[SecurityIssue]:
        issues: List[SecurityIssue] = []

        # ── Probe 1: Wildcard origin from standard response ───────────────────
        acao = response.headers.get("access-control-allow-origin", "")

        if acao == "*":
            issues.append(SecurityIssue(
                id="CORS-001",
                title="CORS Wildcard Origin (*)",
                description=(
                    "The API allows requests from any origin (Access-Control-Allow-Origin: *). "
                    "Any website can make authenticated requests to this API from a user's browser."
                ),
                severity=Severity.HIGH,
                category="CORS Misconfiguration",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                recommendation=(
                    "Replace wildcard with explicit, allowlisted origins. "
                    "Example: Access-Control-Allow-Origin: https://yourdomain.com"
                ),
                cwe_id="CWE-942",
                owasp_ref="A05:2021 – Security Misconfiguration",
            ))

        # ── Probe 2: Simulated cross-origin preflight ─────────────────────────
        await self._probe_cors(url, issues)

        # ── Check 3: CORS + credentials = critical ────────────────────────────
        acac = response.headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            issues.append(SecurityIssue(
                id="CORS-002",
                title="CORS Wildcard with Credentials Allowed (Critical)",
                description=(
                    "The API sets Access-Control-Allow-Origin: * AND "
                    "Access-Control-Allow-Credentials: true. This combination allows any origin "
                    "to make credentialed requests — a critical cross-site request forgery vector."
                ),
                severity=Severity.CRITICAL,
                category="CORS Misconfiguration",
                evidence=f"ACAO: {acao} | ACAC: {acac}",
                recommendation=(
                    "NEVER combine wildcard ACAO with credentials=true. "
                    "Specify exact trusted origins and validate the Origin header server-side."
                ),
                cwe_id="CWE-942",
                owasp_ref="A07:2021 – Identification and Authentication Failures",
            ))

        # ── Check 4: Dangerous methods allowed ────────────────────────────────
        acam = response.headers.get("access-control-allow-methods", "")
        dangerous_methods = {"DELETE", "PATCH", "PUT", "TRACE"}
        found_dangerous = dangerous_methods.intersection(
            {m.strip().upper() for m in acam.split(",")}
        )
        if found_dangerous:
            issues.append(SecurityIssue(
                id="CORS-003",
                title=f"CORS Allows Potentially Dangerous Methods: {', '.join(found_dangerous)}",
                description=(
                    f"The CORS policy permits {', '.join(found_dangerous)} methods from cross-origin "
                    "sources, which could allow destructive operations."
                ),
                severity=Severity.MEDIUM,
                category="CORS Misconfiguration",
                evidence=f"Access-Control-Allow-Methods: {acam}",
                recommendation=(
                    "Restrict allowed methods to the minimum needed. "
                    "Never allow TRACE. Require explicit origin validation for mutation methods."
                ),
                cwe_id="CWE-942",
                owasp_ref="A05:2021 – Security Misconfiguration",
            ))

        return issues

    async def _probe_cors(self, url: str, issues: List[SecurityIssue]) -> None:
        """Send a preflight request with a malicious origin to detect reflection."""
        malicious_origin = "https://evil.attacker.com"
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(settings.SCAN_TIMEOUT_SECONDS),
                headers={"User-Agent": settings.SCAN_USER_AGENT},
            ) as client:
                preflight = await client.options(
                    url,
                    headers={
                        "Origin": malicious_origin,
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "Authorization",
                    },
                )

            reflected = preflight.headers.get("access-control-allow-origin", "")

            if reflected == malicious_origin:
                issues.append(SecurityIssue(
                    id="CORS-004",
                    title="CORS Origin Reflection Vulnerability",
                    description=(
                        "The server blindly reflects the requesting Origin header back "
                        "in the CORS response, allowing any origin to bypass CORS protections."
                    ),
                    severity=Severity.CRITICAL,
                    category="CORS Misconfiguration",
                    evidence=f"Sent Origin: {malicious_origin} | Reflected: {reflected}",
                    recommendation=(
                        "Implement an explicit Origin allowlist. "
                        "Never reflect the Origin header without validating against a known list."
                    ),
                    cwe_id="CWE-942",
                    owasp_ref="A05:2021 – Security Misconfiguration",
                ))

            elif reflected == "null":
                issues.append(SecurityIssue(
                    id="CORS-005",
                    title="CORS Allows 'null' Origin",
                    description=(
                        "The server permits requests with Origin: null, which can be "
                        "triggered from sandboxed iframes or local files."
                    ),
                    severity=Severity.MEDIUM,
                    category="CORS Misconfiguration",
                    evidence=f"Access-Control-Allow-Origin: null",
                    recommendation="Remove 'null' from allowed origins.",
                    cwe_id="CWE-942",
                    owasp_ref="A05:2021 – Security Misconfiguration",
                ))

        except Exception:
            pass  # CORS probe is best-effort
