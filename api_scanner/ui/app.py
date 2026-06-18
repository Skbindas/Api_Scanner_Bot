"""
Main application window for the API Scanner Bot.

Provides the top-level Tkinter window with a tabbed interface,
menu bar, status bar, and coordinates all application modules.
"""

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from typing import Optional

from api_scanner.config import AppConfig
from api_scanner.scanner.models import ScanResult
from api_scanner.ui.async_handler import AsyncHandler
from api_scanner.ui.reports_tab import ReportsTab
from api_scanner.ui.results_tab import ResultsTab
from api_scanner.ui.scanner_tab import ScannerTab
from api_scanner.ui.security_tab import SecurityTab
from api_scanner.ui.widgets import StatusBar


class ScannerApp(tk.Tk):
    """Main application window for API Scanner Pro.

    Provides a professional GUI with tabbed interface for scanning,
    security analysis, results viewing, and report generation.

    Attributes:
        config: Application configuration.
        async_handler: Handler for bridging async operations with Tkinter.
    """

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        """Initialize the ScannerApp.

        Args:
            config: Application configuration. Creates a default if not provided.
        """
        super().__init__()

        self.config = config or AppConfig()
        self.async_handler = AsyncHandler(self)

        self._setup_window()
        self._setup_style()
        self._create_menu()
        self._create_widgets()

        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_window(self) -> None:
        """Configure the main window properties."""
        self.title("API Scanner Pro v2.0")
        self.geometry("1000x700")
        self.minsize(800, 600)

    def _setup_style(self) -> None:
        """Configure ttk styling for a modern look."""
        style = ttk.Style(self)
        style.theme_use("clam")

        # Customize some styles
        style.configure("TNotebook", padding=5)
        style.configure("TNotebook.Tab", padding=(12, 4))
        style.configure("TButton", padding=(8, 4))
        style.configure("TLabelframe.Label", font=("Segoe UI", 9, "bold"))

    def _create_menu(self) -> None:
        """Create the application menu bar."""
        menubar = tk.Menu(self)
        self.configure(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export All", command=self._export_all)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)

        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(
            label="Configure API Key", command=self._configure_api_key
        )

    def _create_widgets(self) -> None:
        """Create and layout all main widgets."""
        # Notebook with tabs
        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Scanner tab
        self._scanner_tab = ScannerTab(
            self._notebook,
            config=self.config,
            async_handler=self.async_handler,
            on_scan_complete=self._on_scan_complete,
        )
        self._notebook.add(self._scanner_tab, text="Scanner")

        # Security tab
        self._security_tab = SecurityTab(
            self._notebook,
            config=self.config,
            async_handler=self.async_handler,
        )
        self._notebook.add(self._security_tab, text="Security")

        # Results tab
        self._results_tab = ResultsTab(self._notebook)
        self._notebook.add(self._results_tab, text="Results")

        # Reports tab
        self._reports_tab = ReportsTab(
            self._notebook,
            config=self.config,
        )
        self._notebook.add(self._reports_tab, text="Reports")

        # Status bar at bottom
        self._status_bar = StatusBar(self)
        self._status_bar.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=(0, 5))

    def _on_scan_complete(self, result: ScanResult) -> None:
        """Handle scan completion across all tabs.

        Updates the security tab target, results tab data, and
        reports tab scan result.

        Args:
            result: The completed scan result.
        """
        self._security_tab.set_target(result.url)
        self._results_tab.populate(result)
        self._reports_tab.set_scan_result(result)
        self._status_bar.set_status(
            f"Scan complete: {len(result.api_endpoints)} endpoints found"
        )

    def _export_all(self) -> None:
        """Export all formats via the reports tab."""
        self._notebook.select(self._reports_tab)
        self._reports_tab._do_export()

    def _configure_api_key(self) -> None:
        """Show dialog to configure the Shodan API key."""
        current_key = self.config.shodan_api_key
        masked = current_key[:4] + "..." if len(current_key) > 4 else current_key

        new_key = simpledialog.askstring(
            "Configure API Key",
            f"Enter Shodan API Key:\n(Current: {masked or 'Not set'})",
            parent=self,
        )

        if new_key is not None:
            try:
                self.config.set_shodan_api_key(new_key)
                self._status_bar.set_status("API key updated.")
            except ValueError as e:
                self._status_bar.set_status(f"Invalid API key: {e}")

    def _on_close(self) -> None:
        """Handle application close event.

        Shuts down the async handler and destroys the window.
        """
        self.async_handler.shutdown()
        self.destroy()
