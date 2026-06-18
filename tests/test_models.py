"""
Tests for data models (scanner models and security models).
"""

from datetime import datetime

import pytest

from api_scanner.scanner.models import (
    CookieData,
    MetaData,
    RequestData,
    ResponseData,
    ScanResult,
    StorageData,
)
from api_scanner.security.models import (
    SecurityFinding,
    ThreatIndicator,
    ThreatReport,
    VulnerabilityInfo,
)


class TestScannerModels:
    """Tests for scanner data models."""

    def test_request_data_creation(self):
        """RequestData can be instantiated with required fields."""
        req = RequestData(url="https://example.com/api", method="GET")
        assert req.url == "https://example.com/api"
        assert req.method == "GET"
        assert req.headers == {}
        assert req.payload is None
        assert isinstance(req.timestamp, datetime)

    def test_response_data_creation(self):
        """ResponseData can be instantiated with required fields."""
        resp = ResponseData(url="https://example.com/api", status_code=200)
        assert resp.url == "https://example.com/api"
        assert resp.status_code == 200
        assert resp.content_type == ""
        assert resp.size == 0

    def test_scan_result_creation(self):
        """ScanResult can be instantiated with all fields."""
        result = ScanResult(
            url="https://example.com",
            requests=[RequestData(url="https://example.com/api", method="GET")],
            responses=[ResponseData(url="https://example.com/api", status_code=200)],
            api_endpoints=[],
            storage_data=StorageData(),
            meta_data=MetaData(title="Test Page"),
            scan_duration=1.5,
            errors=[],
        )
        assert result.url == "https://example.com"
        assert len(result.requests) == 1
        assert len(result.responses) == 1
        assert result.scan_duration == 1.5
        assert result.meta_data.title == "Test Page"


class TestSecurityModels:
    """Tests for security data models."""

    def test_threat_report_creation(self):
        """ThreatReport can be instantiated with all fields."""
        indicator = ThreatIndicator(
            category="phishing",
            description="Suspicious URL detected",
            severity="high",
            evidence="domain mimics paypal.com",
        )
        report = ThreatReport(
            url="http://paypa1.com",
            risk_score=55,
            risk_level="medium",
            indicators=[indicator],
            summary="Potential phishing site detected",
        )
        assert report.url == "http://paypa1.com"
        assert report.risk_score == 55
        assert report.risk_level == "medium"
        assert len(report.indicators) == 1
        assert report.indicators[0].category == "phishing"
        assert isinstance(report.analyzed_at, datetime)

    def test_security_finding_creation(self):
        """SecurityFinding can be instantiated with all fields."""
        vuln = VulnerabilityInfo(
            cve_id="CVE-2021-44228",
            severity="critical",
            description="Log4Shell RCE vulnerability",
        )
        finding = SecurityFinding(
            ip="93.184.216.34",
            organization="Edgecast",
            country="US",
            open_ports=[80, 443, 8080],
            vulnerabilities=[vuln],
            services=[],
            last_update="2024-01-15",
        )
        assert finding.ip == "93.184.216.34"
        assert finding.organization == "Edgecast"
        assert 80 in finding.open_ports
        assert len(finding.vulnerabilities) == 1
        assert finding.vulnerabilities[0].cve_id == "CVE-2021-44228"
