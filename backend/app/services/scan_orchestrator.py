import asyncio
import httpx
from typing import List
from app.scanners import *
from app.cloud_scanners import *

TIMEOUT = httpx.Timeout(6.0, connect=3.0)

async def fetch_response(url: str):
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        return await client.get(url)

async def run_scanners(url: str, response) -> List[dict]:
    scanners = [
        auth_scanner.check_auth,
        headers_scanner.check_headers,
        cors_scanner.check_cors,
        transport_scanner.check_transport,
        response_scanner.check_response,
        status_scanner.check_status,
        anomaly_scanner.detect_anomalies,
        fuzz_scanner.basic_fuzz,
        check_s3_bucket,
        check_exposed_storage,
    ]

    tasks = [asyncio.to_thread(scanner, response if 'response' in scanner.__code__.co_varnames else url) for scanner in scanners]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    issues = []
    for r in results:
        if isinstance(r, list):
            issues.extend(r)

    return issues