"""
Test Suite — Cloud Security Scanner
=====================================
Tests cover:
- API endpoints (scan, bulk-scan, report, history)
- Individual scanner modules
- Input validation
- Scoring logic
"""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from httpx import AsyncClient, Response, Headers

# ── App Import ────────────────────────────────────────────────────────────────
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.main import app
from app.models.schemas import ScanReport, ScanStatus, Severity, SecurityIssue, ScanScore
from app.services.scan_service import ScanService, _compute_score
from app.scanners.header_scanner import HeaderScanner
from app.scanners.cors_scanner import CORSScanner
from app.scanners.transport_scanner import TransportScanner
from app.scanners.response_scanner import ResponseScanner

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def make_mock_response(
    status_code: int = 200,
    headers: dict = None,
    text: str = '{"status": "ok"}',
    url: str = "https://api.example.com/v1/users",
) -> MagicMock:
    """Build a mock httpx.Response for scanner tests."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.headers = Headers(headers or {})
    mock.text = text
    mock.url = url
    mock.history = []
    mock.reason_phrase = "OK"
    mock.extensions = {}
    return mock


# ── Input Validation Tests ────────────────────────────────────────────────────

class TestInputValidation:
    def test_valid_https_url(self, client):
        """Valid HTTPS URL should be accepted."""
        with patch("app.controllers.scan_controller.ScanController.scan_single") as mock_scan:
            mock_scan.return_value = ScanReport(
                scan_id="test-id",
                url="https://httpbin.org/get",
                status=ScanStatus.COMPLETED,
                timestamp=datetime.now(timezone.utc),
            )
            resp = client.post("/api/v1/scan", json={"url": "https://httpbin.org/get"})
            assert resp.status_code == 200

    def test_rejects_http_localhost(self, client):
        """Internal addresses must be rejected."""
        resp = client.post("/api/v1/scan", json={"url": "http://localhost:8080/admin"})
        assert resp.status_code == 422

    def test_rejects_private_ip(self, client):
        resp = client.post("/api/v1/scan", json={"url": "http://192.168.1.1/api"})
        assert resp.status_code == 422

    def test_rejects_invalid_scheme(self, client):
        resp = client.post("/api/v1/scan", json={"url": "ftp://example.com"})
        assert resp.status_code == 422

    def test_rejects_no_host(self, client):
        resp = client.post("/api/v1/scan", json={"url": "https://"})
        assert resp.status_code == 422

    def test_bulk_scan_deduplication(self, client):
        """Duplicate URLs in bulk scan should be deduplicated."""
        from app.models.schemas import BulkScanRequest
        req = BulkScanRequest(urls=[
            "https://api.example.com/v1",
            "https://api.example.com/v1",
            "https://api.example.com/v2",
        ])
        assert len(req.urls) == 2

    def test_bulk_scan_max_urls(self, client):
        urls = [f"https://api.example.com/endpoint-{i}" for i in range(25)]
        resp = client.post("/api/v1/bulk-scan", json={"urls": urls})
        assert resp.status_code == 422


# ── Scoring Tests ─────────────────────────────────────────────────────────────

class TestScoring:
    def _make_issue(self, severity: Severity, n: int = 1):
        return [SecurityIssue(
            id=f"TEST-{i:03d}",
            title="Test Issue",
            description="Test",
            severity=severity,
            category="Test",
            recommendation="Fix it",
        ) for i in range(n)]

    def test_clean_scan_grade_a_plus(self):
        score = _compute_score([])
        assert score.total == 0
        assert score.grade == "A+"

    def test_single_critical_grade_f(self):
        issues = self._make_issue(Severity.CRITICAL, 4)
        score = _compute_score(issues)
        assert score.grade == "F"
        assert score.critical_count == 4

    def test_single_medium_grade_b(self):
        issues = self._make_issue(Severity.MEDIUM, 5)  # 5 * 4 = 20 → B
        score = _compute_score(issues)
        assert score.grade in ("B", "C")

    def test_score_capped_at_100(self):
        issues = self._make_issue(Severity.CRITICAL, 10)
        score = _compute_score(issues)
        assert score.total <= 100

    def test_count_fields(self):
        issues = (
            self._make_issue(Severity.CRITICAL, 2) +
            self._make_issue(Severity.HIGH, 3) +
            self._make_issue(Severity.MEDIUM, 1)
        )
        score = _compute_score(issues)
        assert score.critical_count == 2
        assert score.high_count == 3
        assert score.medium_count == 1
        assert score.low_count == 0


# ── Scanner Module Tests ──────────────────────────────────────────────────────

class TestTransportScanner:
    @pytest.mark.asyncio
    async def test_http_url_is_critical(self):
        scanner = TransportScanner()
        mock = make_mock_response(url="http://api.example.com/data")
        issues = await scanner.scan(url="http://api.example.com/data", response=mock)
        assert any(i.severity == Severity.CRITICAL for i in issues)
        assert any(i.id == "TRANSPORT-001" for i in issues)

    @pytest.mark.asyncio
    async def test_https_no_hsts_is_medium(self):
        scanner = TransportScanner()
        mock = make_mock_response(
            url="https://api.example.com/data",
            headers={},  # No HSTS header
        )
        issues = await scanner.scan(url="https://api.example.com/data", response=mock)
        hsts_issues = [i for i in issues if i.id == "TRANSPORT-002"]
        assert len(hsts_issues) == 1
        assert hsts_issues[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_https_with_hsts_no_transport_issues(self):
        scanner = TransportScanner()
        mock = make_mock_response(
            url="https://api.example.com/data",
            headers={"strict-transport-security": "max-age=31536000; includeSubDomains"},
        )
        issues = await scanner.scan(url="https://api.example.com/data", response=mock)
        transport_issues = [i for i in issues if "TRANSPORT" in i.id]
        assert len(transport_issues) == 0


class TestHeaderScanner:
    @pytest.mark.asyncio
    async def test_missing_all_security_headers(self):
        scanner = HeaderScanner()
        mock = make_mock_response(headers={})
        issues = await scanner.scan(url="https://example.com", response=mock)
        ids = {i.id for i in issues}
        # Must flag all required missing headers
        assert "HEADER-001" in ids  # CSP
        assert "HEADER-002" in ids  # X-Content-Type-Options
        assert "HEADER-003" in ids  # X-Frame-Options

    @pytest.mark.asyncio
    async def test_weak_csp_flagged(self):
        scanner = HeaderScanner()
        mock = make_mock_response(headers={
            "content-security-policy": "default-src 'self' 'unsafe-inline'",
        })
        issues = await scanner.scan(url="https://example.com", response=mock)
        assert any(i.id == "HEADER-006" for i in issues)

    @pytest.mark.asyncio
    async def test_server_version_disclosure(self):
        scanner = HeaderScanner()
        mock = make_mock_response(headers={"server": "nginx/1.24.0"})
        issues = await scanner.scan(url="https://example.com", response=mock)
        assert any(i.id == "HEADER-007" for i in issues)


class TestCORSScanner:
    @pytest.mark.asyncio
    async def test_wildcard_acao_is_high(self):
        scanner = CORSScanner()
        mock = make_mock_response(headers={"access-control-allow-origin": "*"})
        # Mock the preflight probe so it doesn't make real HTTP calls
        with patch.object(scanner, "_probe_cors", new=AsyncMock()):
            issues = await scanner.scan(url="https://example.com", response=mock)
        assert any(i.id == "CORS-001" and i.severity == Severity.HIGH for i in issues)

    @pytest.mark.asyncio
    async def test_wildcard_with_credentials_is_critical(self):
        scanner = CORSScanner()
        mock = make_mock_response(headers={
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        })
        with patch.object(scanner, "_probe_cors", new=AsyncMock()):
            issues = await scanner.scan(url="https://example.com", response=mock)
        assert any(i.id == "CORS-002" and i.severity == Severity.CRITICAL for i in issues)


class TestResponseScanner:
    @pytest.mark.asyncio
    async def test_aws_key_detected(self):
        scanner = ResponseScanner()
        mock = make_mock_response(
            headers={"content-type": "application/json"},
            text='{"key": "AKIAIOSFODNN7EXAMPLE", "user": "admin"}',
        )
        issues = await scanner.scan(url="https://example.com", response=mock)
        assert any("AWS" in i.title for i in issues)
        assert any(i.severity == Severity.CRITICAL for i in issues)

    @pytest.mark.asyncio
    async def test_email_exposure_medium(self):
        scanner = ResponseScanner()
        mock = make_mock_response(
            headers={"content-type": "application/json"},
            text='{"admin_email": "admin@company-internal.com", "role": "admin"}',
        )
        issues = await scanner.scan(url="https://example.com", response=mock)
        assert any("Email" in i.title for i in issues)

    @pytest.mark.asyncio
    async def test_stack_trace_detected(self):
        scanner = ResponseScanner()
        mock = make_mock_response(
            headers={"content-type": "text/html"},
            text="Traceback (most recent call last):\n  File app.py line 42\nKeyError: 'user_id'",
        )
        issues = await scanner.scan(url="https://example.com", response=mock)
        assert any(i.id == "RESPONSE-TRACE" for i in issues)

    @pytest.mark.asyncio
    async def test_clean_response_no_issues(self):
        scanner = ResponseScanner()
        mock = make_mock_response(
            headers={"content-type": "application/json"},
            text='{"status": "ok", "message": "Welcome"}',
        )
        issues = await scanner.scan(url="https://example.com", response=mock)
        assert len(issues) == 0


# ── Health Endpoint ───────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_liveness(self, client):
        resp = client.get("/health/")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ── Report Endpoint ───────────────────────────────────────────────────────────

class TestReportEndpoint:
    def test_report_not_found(self, client):
        with patch("app.controllers.report_controller.ReportController.get_report") as mock_get:
            from fastapi import HTTPException
            mock_get.side_effect = HTTPException(status_code=404, detail="Report not found: nonexistent-id")
            resp = client.get("/api/v1/report/nonexistent-id")
            assert resp.status_code == 404
