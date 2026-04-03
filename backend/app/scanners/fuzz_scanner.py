import httpx
from urllib.parse import quote

# Payloads covering SQLi, XSS, and path traversal
PAYLOADS = [
    "'",                          # SQL injection
    "<script>alert(1)</script>",  # XSS
    "../../etc/passwd",           # Path traversal
]

async def fuzz_api(url: str) -> list:
    issues = []

    async with httpx.AsyncClient(timeout=5) as client:
        for payload in PAYLOADS:
            try:
                res = await client.get(f"{url}?input={quote(payload)}")

                if res.status_code >= 500:
                    issues.append({
                        "issue": "Possible Injection Vulnerability",
                        "severity": "High",
                        "confidence": "Medium",
                        "recommendation": "Sanitize and validate all user-supplied input server-side."
                    })

            except httpx.TimeoutException:
                # Timeout may itself indicate a vulnerability (e.g. sleep-based SQLi)
                issues.append({
                    "issue": "Request Timeout During Fuzzing",
                    "severity": "Medium",
                    "confidence": "Low",
                    "recommendation": "Investigate whether input causes server-side delays (blind SQLi)."
                })

            except httpx.RequestError:
                # Network/connection error — skip silently
                pass

    return issues  # ✅ FIX: was `return issues()` — lists are not callable