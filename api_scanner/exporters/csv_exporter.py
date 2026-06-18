"""
CSV exporter for scan results.

Exports network requests and API endpoints to CSV format using
pandas DataFrames for clean tabular output.
"""

from pathlib import Path

import pandas as pd

from api_scanner.exceptions import ExportError
from api_scanner.exporters.base import BaseExporter
from api_scanner.scanner.models import ScanResult


class CSVExporter(BaseExporter):
    """Exports scan results to CSV files using pandas.

    Generates separate CSV files for network requests and API endpoints,
    organized within the specified output path.
    """

    def export(self, scan_result: ScanResult, output_path: str) -> str:
        """Export scan results to CSV files.

        Creates two CSV files:
        - requests.csv: All captured network requests
        - api_endpoints.csv: Identified API endpoint calls

        Args:
            scan_result: The scan result data to export.
            output_path: The directory or file path for the CSV output.

        Returns:
            The path to the main CSV file (requests.csv).

        Raises:
            ExportError: If the export operation fails.
        """
        try:
            output_dir = Path(output_path)
            if output_dir.suffix:
                output_dir = output_dir.parent
            output_dir.mkdir(parents=True, exist_ok=True)

            # Export all network requests
            requests_path = output_dir / "requests.csv"
            requests_data = []
            for req in scan_result.requests:
                requests_data.append({
                    "url": req.url,
                    "method": req.method,
                    "timestamp": req.timestamp.isoformat(),
                    "has_payload": req.payload is not None,
                })

            requests_df = pd.DataFrame(requests_data)
            requests_df.to_csv(requests_path, index=False, encoding="utf-8")

            # Export API endpoints
            endpoints_path = output_dir / "api_endpoints.csv"
            endpoints_data = []
            for endpoint in scan_result.api_endpoints:
                endpoints_data.append({
                    "url": endpoint.url,
                    "method": endpoint.method,
                    "timestamp": endpoint.timestamp.isoformat(),
                    "has_payload": endpoint.payload is not None,
                })

            endpoints_df = pd.DataFrame(endpoints_data)
            endpoints_df.to_csv(endpoints_path, index=False, encoding="utf-8")

            # Export responses if available
            if scan_result.responses:
                responses_path = output_dir / "responses.csv"
                responses_data = []
                for resp in scan_result.responses:
                    responses_data.append({
                        "url": resp.url,
                        "status_code": resp.status_code,
                        "content_type": resp.content_type,
                        "size": resp.size,
                    })

                responses_df = pd.DataFrame(responses_data)
                responses_df.to_csv(responses_path, index=False, encoding="utf-8")

            return str(requests_path)

        except Exception as e:
            raise ExportError(f"Failed to export CSV: {e}") from e
