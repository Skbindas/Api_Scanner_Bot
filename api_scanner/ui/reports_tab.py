"""
Reports tab for the API Scanner Bot GUI.

Provides export controls for generating scan reports in multiple
formats (JSON, CSV, HTML) with directory selection and status display.
"""

import tkinter as tk
from tkinter import ttk, filedialog
from typing import Optional

from api_scanner.config import AppConfig
from api_scanner.exporters.export_manager import ExportManager
from api_scanner.scanner.models import ScanResult
from api_scanner.ui.widgets import LogConsole


class ReportsTab(ttk.Frame):
    """Reports tab providing export functionality.

    Contains format selection checkboxes, output directory selector,
    export button, and status label showing last export path.

    Attributes:
        config: Application configuration.
    """

    def __init__(
        self,
        parent: tk.Widget,
        config: AppConfig,
        **kwargs: object,
    ) -> None:
        """Initialize the ReportsTab.

        Args:
            parent: Parent widget.
            config: Application configuration instance.
            **kwargs: Additional keyword arguments for ttk.Frame.
        """
        super().__init__(parent, **kwargs)
        self.config = config
        self._scan_result: Optional[ScanResult] = None
        self._export_manager = ExportManager(config)

        self._create_widgets()

    def _create_widgets(self) -> None:
        """Create and layout all widgets for the reports tab."""
        # Format selection
        format_frame = ttk.LabelFrame(self, text="Export Formats", padding=10)
        format_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        self._json_var = tk.BooleanVar(value=True)
        self._csv_var = tk.BooleanVar(value=True)
        self._html_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(
            format_frame, text="JSON Report", variable=self._json_var
        ).pack(side=tk.LEFT, padx=(0, 20))

        ttk.Checkbutton(
            format_frame, text="CSV Data", variable=self._csv_var
        ).pack(side=tk.LEFT, padx=(0, 20))

        ttk.Checkbutton(
            format_frame, text="HTML Report", variable=self._html_var
        ).pack(side=tk.LEFT)

        # Output directory
        dir_frame = ttk.LabelFrame(self, text="Output Directory", padding=10)
        dir_frame.pack(fill=tk.X, padx=10, pady=5)

        self._dir_var = tk.StringVar(value=self.config.output_dir)
        dir_entry = ttk.Entry(dir_frame, textvariable=self._dir_var, width=50)
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        ttk.Button(
            dir_frame, text="Browse...", command=self._browse_directory, width=10
        ).pack(side=tk.LEFT)

        # Export button
        export_frame = ttk.Frame(self, padding=10)
        export_frame.pack(fill=tk.X, padx=10)

        self._export_btn = ttk.Button(
            export_frame, text="Export Reports", command=self._do_export, width=20
        )
        self._export_btn.pack(side=tk.LEFT)

        # Status label
        self._status_var = tk.StringVar(value="No export performed yet.")
        ttk.Label(
            export_frame, textvariable=self._status_var, foreground="gray"
        ).pack(side=tk.LEFT, padx=(15, 0))

        # Log console
        log_frame = ttk.LabelFrame(self, text="Export Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        self._log = LogConsole(log_frame, height=8)
        self._log.pack(fill=tk.BOTH, expand=True)

    def set_scan_result(self, result: ScanResult) -> None:
        """Set the scan result to be exported.

        Args:
            result: The scan result available for export.
        """
        self._scan_result = result
        self._log.log("Scan result loaded. Ready to export.", "success")

    def _browse_directory(self) -> None:
        """Open a directory selection dialog."""
        directory = filedialog.askdirectory(
            initialdir=self._dir_var.get(),
            title="Select Output Directory",
        )
        if directory:
            self._dir_var.set(directory)

    def _do_export(self) -> None:
        """Perform the export operation."""
        if not self._scan_result:
            self._log.log("No scan results available to export.", "error")
            self._status_var.set("Error: No scan data available.")
            return

        formats = []
        if self._json_var.get():
            formats.append("json")
        if self._csv_var.get():
            formats.append("csv")
        if self._html_var.get():
            formats.append("html")

        if not formats:
            self._log.log("No export formats selected.", "error")
            self._status_var.set("Error: Select at least one format.")
            return

        self._export_btn.configure(state=tk.DISABLED)
        self._log.log(f"Exporting in formats: {', '.join(formats)}...", "info")

        try:
            # Update config output dir if changed
            self.config.output_dir = self._dir_var.get()
            self._export_manager = ExportManager(self.config)

            results = self._export_manager.export_all(self._scan_result, formats)

            for fmt, path in results.items():
                self._log.log(f"  {fmt.upper()}: {path}", "success")

            self._status_var.set(f"Exported to: {list(results.values())[0]}")
            self._log.log("Export complete!", "success")

        except Exception as e:
            self._log.log(f"Export failed: {e}", "error")
            self._status_var.set(f"Error: {e}")

        finally:
            self._export_btn.configure(state=tk.NORMAL)
