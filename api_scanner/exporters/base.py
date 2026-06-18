"""
Abstract base class for all scan result exporters.

Defines the interface that all exporter implementations must follow,
ensuring consistent behavior across different output formats.
"""

from abc import ABC, abstractmethod

from api_scanner.scanner.models import ScanResult


class BaseExporter(ABC):
    """Abstract base class for scan result exporters.

    All exporters must implement the export() method which takes a
    ScanResult and an output path, writes the exported data, and
    returns the path to the created file.
    """

    @abstractmethod
    def export(self, scan_result: ScanResult, output_path: str) -> str:
        """Export scan results to a file.

        Args:
            scan_result: The scan result data to export.
            output_path: The file path where the export should be written.

        Returns:
            The path to the created export file.

        Raises:
            ExportError: If the export operation fails.
        """
        ...
