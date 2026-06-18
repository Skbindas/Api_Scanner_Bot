"""
Scanner tab for the API Scanner Bot GUI.

Provides the main scanning interface with URL input, scan controls,
progress indication, and results display in a treeview table.
"""

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Optional

from api_scanner.config import AppConfig
from api_scanner.scanner.models import ScanResult
from api_scanner.scanner.network_scanner import NetworkScanner
from api_scanner.ui.async_handler import AsyncHandler
from api_scanner.ui.widgets import LogConsole, URLInput


class ScannerTab(ttk.Frame):
    """Scanner tab providing URL scanning functionality.

    Contains a URL input field with validation, scan button with progress
    bar, results treeview showing found API endpoints, and a log console
    for real-time scan progress messages.

    Attributes:
        config: Application configuration.
        async_handler: Handler for running async operations.
        last_result: The most recent scan result, if available.
    """

    def __init__(
        self,
        parent: tk.Widget,
        config: AppConfig,
        async_handler: AsyncHandler,
        on_scan_complete: Optional[Callable[[ScanResult], None]] = None,
        **kwargs: object,
    ) -> None:
        """Initialize the ScannerTab.

        Args:
            parent: Parent widget.
            config: Application configuration instance.
            async_handler: Handler for async operations.
            on_scan_complete: Optional callback invoked when a scan completes.
            **kwargs: Additional keyword arguments for ttk.Frame.
        """
        super().__init__(parent, **kwargs)
        self.config = config
        self.async_handler = async_handler
        self._on_scan_complete = on_scan_complete
        self.last_result: Optional[ScanResult] = None
        self._scanning = False

        self._create_widgets()

    def _create_widgets(self) -> None:
        """Create and layout all widgets for the scanner tab."""
        # URL Input section
        input_frame = ttk.LabelFrame(self, text="Target URL", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        self._url_input = URLInput(input_frame)
        self._url_input.pack(fill=tk.X, pady=(0, 5))

        # Controls frame
        controls_frame = ttk.Frame(input_frame)
        controls_frame.pack(fill=tk.X)

        self._scan_btn = ttk.Button(
            controls_frame, text="Scan", command=self._start_scan, width=15
        )
        self._scan_btn.pack(side=tk.LEFT)

        self._progress = ttk.Progressbar(
            controls_frame, mode="indeterminate", length=200
        )
        self._progress.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

        # Results section
        results_frame = ttk.LabelFrame(
            self, text="API Endpoints Found", padding=10
        )
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Treeview for endpoints
        columns = ("url", "method", "status")
        self._tree = ttk.Treeview(
            results_frame, columns=columns, show="headings", height=8
        )
        self._tree.heading("url", text="URL")
        self._tree.heading("method", text="Method")
        self._tree.heading("status", text="Status")
        self._tree.column("url", width=500)
        self._tree.column("method", width=80)
        self._tree.column("status", width=80)

        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(
            results_frame, orient=tk.VERTICAL, command=self._tree.yview
        )
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Log console
        log_frame = ttk.LabelFrame(self, text="Scan Log", padding=5)
        log_frame.pack(fill=tk.X, padx=10, pady=(5, 10))

        self._log = LogConsole(log_frame, height=6)
        self._log.pack(fill=tk.X)

    def _start_scan(self) -> None:
        """Start the scanning process.

        Validates the URL, then submits the scan coroutine to the
        async handler. Updates UI state to show scanning in progress.
        """
        if self._scanning:
            return

        url = self._url_input.get_url()
        if not self._url_input.is_valid():
            self._log.log("Invalid URL. Please enter a valid HTTP/HTTPS URL.", "error")
            return

        # Clear previous results
        for item in self._tree.get_children():
            self._tree.delete(item)

        self._scanning = True
        self._scan_btn.configure(state=tk.DISABLED)
        self._progress.start(10)
        self._log.log(f"Starting scan of {url}...", "info")

        # Create scanner and submit async task
        scanner = NetworkScanner(self.config)
        self.async_handler.submit(
            scanner.scan(url),
            on_complete=self._on_scan_done,
            on_error=self._on_scan_error,
        )

    def _on_scan_done(self, result: ScanResult) -> None:
        """Handle scan completion.

        Updates the UI with scan results, populates the treeview,
        and notifies any registered callback.

        Args:
            result: The completed scan result.
        """
        self._scanning = False
        self._scan_btn.configure(state=tk.NORMAL)
        self._progress.stop()
        self.last_result = result

        # Populate treeview with API endpoints
        for endpoint in result.api_endpoints:
            # Find matching response for status
            status = ""
            for resp in result.responses:
                if resp.url == endpoint.url:
                    status = str(resp.status_code)
                    break

            self._tree.insert(
                "", tk.END, values=(endpoint.url, endpoint.method, status)
            )

        self._log.log(
            f"Scan complete! Found {len(result.api_endpoints)} API endpoints "
            f"({len(result.requests)} total requests in {result.scan_duration:.2f}s)",
            "success",
        )

        if result.errors:
            for error in result.errors:
                self._log.log(f"Error: {error}", "warning")

        # Notify callback
        if self._on_scan_complete:
            self._on_scan_complete(result)

    def _on_scan_error(self, error: Exception) -> None:
        """Handle scan failure.

        Updates the UI to show the error and re-enables the scan button.

        Args:
            error: The exception that occurred during scanning.
        """
        self._scanning = False
        self._scan_btn.configure(state=tk.NORMAL)
        self._progress.stop()
        self._log.log(f"Scan failed: {error}", "error")
