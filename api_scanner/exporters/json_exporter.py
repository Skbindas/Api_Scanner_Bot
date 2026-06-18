"""
JSON exporter for scan results.

Exports ScanResult data to a well-formatted JSON file with metadata
including scanner version, export timestamp, and target URL.
"""

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from api_scanner import __version__
from api_scanner.exceptions import ExportError
from api_scanner.exporters.base import BaseExporter
from api_scanner.scanner.models import ScanResult
from api_scanner.utils import safe_json_serialize


class JSONExporter(BaseExporter):
    """Exports scan results to formatted JSON files.

    Includes metadata such as scanner version, export timestamp,
    and target URL. Uses safe_json_serialize for handling datetime
    and bytes objects.
    """

    def export(self, scan_result: ScanResult, output_path: str) -> str:
        """Export scan results to a JSON file.

        Args:
            scan_result: The scan result data to export.
            output_path: The file path where the JSON should be written.

        Returns:
            The path to the created JSON file.

        Raises:
            ExportError: If the export operation fails.
        """
        try:
            file_path = Path(output_path)
            if not file_path.suffix:
                file_path = file_path.with_suffix(".json")

            # Build the export document with metadata
            export_data: dict[str, Any] = {
                "metadata": {
                    "scanner_version": __version__,
                    "export_time": datetime.now().isoformat(),
                    "target_url": scan_result.url,
                    "scan_duration": scan_result.scan_duration,
                    "scan_timestamp": scan_result.timestamp.isoformat(),
                },
                "scan_result": asdict(scan_result),
            }

            # Serialize using safe_json_serialize for proper type handling
            json_content = safe_json_serialize(export_data)

            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(json_content, encoding="utf-8")

            return str(file_path)

        except Exception as e:
            raise ExportError(f"Failed to export JSON: {e}") from e
