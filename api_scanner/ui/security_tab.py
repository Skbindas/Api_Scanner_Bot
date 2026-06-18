"""
Security tab for the API Scanner Bot GUI.

Provides security analysis functionality including Shodan scanning
and heuristic threat analysis with color-coded risk indicators.
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional
from urllib.parse import urlparse

from api_scanner.config import AppConfig
from api_scanner.scanner.models import ScanResult
from api_scanner.security.models import SecurityFinding, ThreatReport
from api_scanner.security.shodan_scanner import ShodanScanner
from api_scanner.security.threat_analyzer import ThreatAnalyzer
from api_scanner.ui.async_handler import AsyncHandler
from api_scanner.ui.widgets import LogConsole, RiskBadge


class SecurityTab(ttk.Frame):
    """Security tab providing Shodan and threat analysis.

    Contains controls for running security scans, displays Shodan
    results in a labeled frame, and shows threat analysis with
    color-coded risk levels.

    Attributes:
        config: Application configuration.
        async_handler: Handler for running async operations.
    """

    def __init__(
        self,
        parent: tk.Widget,
        config: AppConfig,
        async_handler: AsyncHandler,
        **kwargs: object,
    ) -> None:
        """Initialize the SecurityTab.

        Args:
            parent: Parent widget.
            config: Application configuration instance.
            async_handler: Handler for async operations.
            **kwargs: Additional keyword arguments for ttk.Frame.
        """
        super().__init__(parent, **kwargs)
        self.config = config
        self.async_handler = async_handler
        self._scanning = False
        self._target_url: str = ""

        self._create_widgets()

    def _create_widgets(self) -> None:
        """Create and layout all widgets for the security tab."""
        # Controls
        controls_frame = ttk.Frame(self, padding=10)
        controls_frame.pack(fill=tk.X)

        self._check_btn = ttk.Button(
            controls_frame,
            text="Check Security",
            command=self._start_security_check,
            width=20,
        )
        self._check_btn.pack(side=tk.LEFT)

        self._progress = ttk.Progressbar(
            controls_frame, mode="indeterminate", length=200
        )
        self._progress.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

        # Shodan results frame
        shodan_frame = ttk.LabelFrame(self, text="Shodan Results", padding=10)
        shodan_frame.pack(fill=tk.X, padx=10, pady=5)

        # Shodan info grid
        self._shodan_labels: dict[str, ttk.Label] = {}
        info_fields = [
            ("IP Address", "ip"),
            ("Organization", "org"),
            ("Open Ports", "ports"),
            ("CVEs", "cves"),
        ]

        for row, (label_text, key) in enumerate(info_fields):
            ttk.Label(shodan_frame, text=f"{label_text}:", font=("Segoe UI", 9, "bold")).grid(
                row=row, column=0, sticky=tk.W, padx=(0, 10), pady=2
            )
            value_label = ttk.Label(shodan_frame, text="N/A", wraplength=500)
            value_label.grid(row=row, column=1, sticky=tk.W, pady=2)
            self._shodan_labels[key] = value_label

        # Threat analysis frame
        threat_frame = ttk.LabelFrame(self, text="Threat Analysis", padding=10)
        threat_frame.pack(fill=tk.X, padx=10, pady=5)

        # Risk badge
        risk_row = ttk.Frame(threat_frame)
        risk_row.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(risk_row, text="Risk Level:", font=("Segoe UI", 9, "bold")).pack(
            side=tk.LEFT, padx=(0, 10)
        )
        self._risk_badge = RiskBadge(risk_row)
        self._risk_badge.pack(side=tk.LEFT)

        self._risk_score_label = ttk.Label(risk_row, text="Score: -")
        self._risk_score_label.pack(side=tk.LEFT, padx=(10, 0))

        # Findings list
        ttk.Label(threat_frame, text="Findings:", font=("Segoe UI", 9, "bold")).pack(
            anchor=tk.W
        )

        columns = ("category", "severity", "description")
        self._findings_tree = ttk.Treeview(
            threat_frame, columns=columns, show="headings", height=5
        )
        self._findings_tree.heading("category", text="Category")
        self._findings_tree.heading("severity", text="Severity")
        self._findings_tree.heading("description", text="Description")
        self._findings_tree.column("category", width=120)
        self._findings_tree.column("severity", width=80)
        self._findings_tree.column("description", width=400)
        self._findings_tree.pack(fill=tk.X, pady=(5, 0))

        # Log console
        log_frame = ttk.LabelFrame(self, text="Security Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        self._log = LogConsole(log_frame, height=5)
        self._log.pack(fill=tk.BOTH, expand=True)

    def set_target(self, url: str) -> None:
        """Set the target URL for security analysis.

        Args:
            url: The URL to analyze.
        """
        self._target_url = url

    def _start_security_check(self) -> None:
        """Start the security check process.

        Runs Shodan scan and threat analysis using the async handler.
        """
        if self._scanning:
            return

        if not self._target_url:
            self._log.log("No target URL set. Run a scan first.", "error")
            return

        self._scanning = True
        self._check_btn.configure(state=tk.DISABLED)
        self._progress.start(10)
        self._log.log(f"Starting security check for {self._target_url}...", "info")

        # Run Shodan scan
        self._run_shodan_scan()

    def _run_shodan_scan(self) -> None:
        """Run the Shodan scan asynchronously."""
        try:
            parsed = urlparse(self._target_url)
            domain = parsed.hostname or ""
        except Exception:
            domain = ""

        if not domain:
            self._log.log("Could not extract domain from URL.", "error")
            self._run_threat_analysis()
            return

        if not self.config.shodan_api_key:
            self._log.log("No Shodan API key configured. Skipping Shodan scan.", "warning")
            self._update_shodan_results(None)
            self._run_threat_analysis()
            return

        scanner = ShodanScanner(self.config)
        self.async_handler.submit(
            scanner.scan(domain),
            on_complete=self._on_shodan_done,
            on_error=self._on_shodan_error,
        )

    def _on_shodan_done(self, result: Optional[SecurityFinding]) -> None:
        """Handle Shodan scan completion.

        Args:
            result: The security finding, or None if nothing found.
        """
        self._update_shodan_results(result)
        if result:
            self._log.log("Shodan scan complete.", "success")
        else:
            self._log.log("No Shodan data available for this host.", "warning")

        # Continue with threat analysis
        self._run_threat_analysis()

    def _on_shodan_error(self, error: Exception) -> None:
        """Handle Shodan scan failure.

        Args:
            error: The exception that occurred.
        """
        self._log.log(f"Shodan scan failed: {error}", "error")
        self._update_shodan_results(None)
        self._run_threat_analysis()

    def _run_threat_analysis(self) -> None:
        """Run the threat analysis asynchronously."""
        self._log.log("Running threat analysis...", "info")
        analyzer = ThreatAnalyzer()

        self.async_handler.submit(
            analyzer.analyze_url(self._target_url),
            on_complete=self._on_threat_done,
            on_error=self._on_threat_error,
        )

    def _on_threat_done(self, report: ThreatReport) -> None:
        """Handle threat analysis completion.

        Args:
            report: The threat analysis report.
        """
        self._scanning = False
        self._check_btn.configure(state=tk.NORMAL)
        self._progress.stop()

        # Update risk badge
        self._risk_badge.set_risk(report.risk_level)
        self._risk_score_label.configure(text=f"Score: {report.risk_score}/100")

        # Populate findings tree
        for item in self._findings_tree.get_children():
            self._findings_tree.delete(item)

        for indicator in report.indicators:
            self._findings_tree.insert(
                "",
                tk.END,
                values=(indicator.category, indicator.severity, indicator.description),
            )

        self._log.log(
            f"Threat analysis complete. Risk: {report.risk_level} ({report.risk_score}/100)",
            "success" if report.risk_score < 30 else "warning",
        )

    def _on_threat_error(self, error: Exception) -> None:
        """Handle threat analysis failure.

        Args:
            error: The exception that occurred.
        """
        self._scanning = False
        self._check_btn.configure(state=tk.NORMAL)
        self._progress.stop()
        self._log.log(f"Threat analysis failed: {error}", "error")

    def _update_shodan_results(self, finding: Optional[SecurityFinding]) -> None:
        """Update the Shodan results display.

        Args:
            finding: The security finding to display, or None.
        """
        if finding is None:
            for label in self._shodan_labels.values():
                label.configure(text="N/A")
            return

        self._shodan_labels["ip"].configure(text=finding.ip)
        self._shodan_labels["org"].configure(text=finding.organization)
        self._shodan_labels["ports"].configure(
            text=", ".join(str(p) for p in finding.open_ports) or "None"
        )

        cves = [v.cve_id for v in finding.vulnerabilities]
        self._shodan_labels["cves"].configure(
            text=", ".join(cves) if cves else "None found"
        )
