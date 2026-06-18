"""
Export manager for coordinating multiple export formats.

Manages the export process across all formats, creating timestamped
output directories and delegating to individual exporters.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from api_scanner.config import AppConfig
from api_scanner.exceptions import ExportError
from api_scanner.exporters.csv_exporter import CSVExporter
from api_scanner.exporters.html_exporter import HTMLExporter
from api_scanner.exporters.json_exporter import JSONExporter
from api_scanner.scanner.models import ScanResult
from api_scanner.utils import ensure_directories


class ExportManager:
    """Coordinates all export operations for scan results.

    Creates timestamped subdirectories within the configured output directory
    and delegates to individual exporters for each format.

    Attributes:
        config: Application configuration containing output directory settings.
    """

    def __init__(self, config: AppConfig) -> None:
        """Initialize the ExportManager.

        Args:
            config: Application configuration instance.
        """
        self.config = config
        self._exporters = {
            "json": JSONExporter(),
            "csv": CSVExporter(),
            "html": HTMLExporter(),
        }

    def export_all(
        self,
        scan_result: ScanResult,
        formats: Optional[list[str]] = None,
    ) -> dict[str, str]:
        """Export scan results in multiple formats.

        Creates a timestamped subdirectory and exports the scan results
        in all requested formats.

        Args:
            scan_result: The scan result data to export.
            formats: List of format names to export. Defaults to all formats
                     (json, csv, html).

        Returns:
            Dictionary mapping format names to the paths of created files.

        Raises:
            ExportError: If any export operation fails.
        """
        if formats is None:
            formats = ["json", "csv", "html"]

        # Validate requested formats
        invalid = [f for f in formats if f not in self._exporters]
        if invalid:
            raise ExportError(
                f"Unsupported export format(s): {', '.join(invalid)}. "
                f"Supported formats: {', '.join(self._exporters.keys())}"
            )

        # Create timestamped output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(self.config.output_dir) / f"scan_{timestamp}"
        ensure_directories(str(output_dir))

        results: dict[str, str] = {}

        for fmt in formats:
            exporter = self._exporters[fmt]

            if fmt == "csv":
                # CSV exporter works with a directory
                output_path = str(output_dir / "csv")
            else:
                output_path = str(output_dir / f"report.{fmt}")

            try:
                result_path = exporter.export(scan_result, output_path)
                results[fmt] = result_path
            except ExportError:
                raise
            except Exception as e:
                raise ExportError(
                    f"Failed to export {fmt} format: {e}"
                ) from e

        return results
