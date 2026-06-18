"""
Shared test fixtures for the API Scanner Bot test suite.
"""

import os
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from api_scanner.config import AppConfig
from api_scanner.scanner.models import (
    MetaData,
    RequestData,
    ResponseData,
    ScanResult,
    StorageData,
)
from api_scanner.security.models import ThreatIndicator, ThreatReport


@pytest.fixture
def app_config() -> AppConfig:
    """Create an AppConfig instance with test defaults.

    Returns:
        AppConfig instance with default values (environment variables cleared).
    """
    with patch.dict(os.environ, {}, clear=True):
        env = {
            "SHODAN_API_KEY": "test_key_123",
            "SCAN_TIMEOUT": "30",
            "MAX_RETRIES": "3",
            "RATE_LIMIT_DELAY": "1.0",
            "OUTPUT_DIR": "scan_results",
            "HEADLESS": "true",
            "LOG_LEVEL": "INFO",
        }
        with patch.dict(os.environ, env):
            config = AppConfig()
    return config


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Return a pre-built ScanResult with realistic data.

    Returns:
        ScanResult populated with sample requests, responses, and metadata.
    """
    requests = [
        RequestData(
            url="https://api.example.com/v1/users",
            method="GET",
            headers={"Authorization": "Bearer token123"},
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
        ),
        RequestData(
            url="https://api.example.com/v1/posts",
            method="POST",
            headers={"Content-Type": "application/json"},
            payload='{"title": "Hello", "body": "World"}',
            timestamp=datetime(2024, 1, 15, 10, 0, 1),
        ),
        RequestData(
            url="https://cdn.example.com/static/app.js",
            method="GET",
            headers={},
            timestamp=datetime(2024, 1, 15, 10, 0, 2),
        ),
    ]

    responses = [
        ResponseData(
            url="https://api.example.com/v1/users",
            status_code=200,
            content_type="application/json",
            size=2048,
        ),
        ResponseData(
            url="https://api.example.com/v1/posts",
            status_code=201,
            content_type="application/json",
            size=512,
        ),
    ]

    return ScanResult(
        url="https://example.com",
        requests=requests,
        responses=responses,
        api_endpoints=requests[:2],
        storage_data=StorageData(
            local_storage={"theme": "dark", "lang": "en"},
            session_storage={"token": "abc123"},
        ),
        meta_data=MetaData(
            title="Example Site",
            description="A sample website for testing",
        ),
        scan_duration=3.45,
        errors=[],
        timestamp=datetime(2024, 1, 15, 10, 0, 0),
    )


@pytest.fixture
def sample_threat_report() -> ThreatReport:
    """Return a pre-built ThreatReport for testing.

    Returns:
        ThreatReport with sample threat indicators.
    """
    indicators = [
        ThreatIndicator(
            category="phishing",
            description="URL uses an IP address instead of a domain name",
            severity="critical",
            evidence="Host: 192.168.1.100",
        ),
        ThreatIndicator(
            category="phishing",
            description="URL path contains suspicious keywords",
            severity="high",
            evidence="Keywords found: login, verify",
        ),
    ]

    return ThreatReport(
        url="http://192.168.1.100/login/verify",
        risk_score=55,
        risk_level="medium",
        indicators=indicators,
        summary="Found 2 threat indicator(s). Risk level: medium (score: 55/100).",
        analyzed_at=datetime(2024, 1, 15, 12, 0, 0),
    )


@pytest.fixture
def tmp_output_dir(tmp_path: Path) -> str:
    """Return a tmp_path based output directory for tests.

    Args:
        tmp_path: pytest built-in temporary path fixture.

    Returns:
        String path to a temporary output directory.
    """
    output_dir = tmp_path / "test_scan_results"
    output_dir.mkdir(parents=True, exist_ok=True)
    return str(output_dir)


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> str:
    """Provide a temporary directory for scan output.

    Args:
        tmp_path: pytest built-in temporary path fixture.

    Returns:
        String path to a temporary output directory.
    """
    output_dir = str(tmp_path / "scan_results")
    return output_dir
