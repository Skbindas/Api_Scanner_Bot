"""
Tests for the export system (JSON, CSV, HTML exporters and ExportManager).
"""

import json
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from api_scanner.config import AppConfig
from api_scanner.exporters.csv_exporter import CSVExporter
from api_scanner.exporters.export_manager import ExportManager
from api_scanner.exporters.html_exporter import HTMLExporter
from api_scanner.exporters.json_exporter import JSONExporter
from api_scanner.scanner.models import (
    RequestData,
    ResponseData,
    ScanResult,
    StorageData,
)


@pytest.fixture
def mock_scan_result():
    """Create a mock ScanResult with realistic test data."""
    requests = [
        RequestData(
            url="https://api.example.com/users",
            method="GET",
            headers={"Accept": "application/json"},
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
        ),
        RequestData(
            url="https://api.example.com/posts",
            method="POST",
            headers={"Content-Type": "application/json"},
            payload='{"title": "Test"}',
            timestamp=datetime(2024, 1, 15, 10, 0, 1),
        ),
    ]

    responses = [
        ResponseData(
            url="https://api.example.com/users",
            status_code=200,
            content_type="application/json",
            size=1024,
        ),
    ]

    return ScanResult(
        url="https://example.com",
        requests=requests,
        responses=responses,
        api_endpoints=requests,
        storage_data=StorageData(),
        scan_duration=2.5,
        errors=[],
        timestamp=datetime(2024, 1, 15, 10, 0, 0),
    )


class TestJSONExporter:
    """Tests for JSONExporter."""

    def test_json_exporter(self, mock_scan_result, tmp_path):
        """JSON exporter creates valid JSON with expected keys."""
        exporter = JSONExporter()
        output_path = str(tmp_path / "report.json")

        result_path = exporter.export(mock_scan_result, output_path)

        assert Path(result_path).exists()
        with open(result_path, "r") as f:
            data = json.load(f)

        assert "metadata" in data
        assert "scan_result" in data
        assert data["metadata"]["target_url"] == "https://example.com"
        assert "scanner_version" in data["metadata"]


class TestCSVExporter:
    """Tests for CSVExporter."""

    def test_csv_exporter(self, mock_scan_result, tmp_path):
        """CSV exporter creates files with expected columns."""
        exporter = CSVExporter()
        output_path = str(tmp_path / "csv_output")

        result_path = exporter.export(mock_scan_result, output_path)

        requests_csv = Path(result_path)
        assert requests_csv.exists()

        content = requests_csv.read_text()
        assert "url" in content
        assert "method" in content
        assert "timestamp" in content
        assert "https://api.example.com/users" in content


class TestHTMLExporter:
    """Tests for HTMLExporter."""

    def test_html_exporter(self, mock_scan_result, tmp_path):
        """HTML exporter creates valid HTML with expected sections."""
        exporter = HTMLExporter()
        output_path = str(tmp_path / "report.html")

        result_path = exporter.export(mock_scan_result, output_path)

        assert Path(result_path).exists()
        content = Path(result_path).read_text()

        assert "<!DOCTYPE html>" in content
        assert "API Scanner Pro Report" in content
        assert "Scan Summary" in content
        assert "https://example.com" in content


class TestExportManager:
    """Tests for ExportManager."""

    def test_export_manager(self, mock_scan_result, tmp_path):
        """ExportManager creates files in all formats."""
        with patch.dict(os.environ, {}, clear=True):
            config = AppConfig()
            config.output_dir = str(tmp_path / "exports")

        manager = ExportManager(config)
        results = manager.export_all(mock_scan_result, formats=["json", "csv", "html"])

        assert "json" in results
        assert "csv" in results
        assert "html" in results

        # Verify files exist
        assert Path(results["json"]).exists()
        assert Path(results["csv"]).exists()
        assert Path(results["html"]).exists()
