"""
Results tab for the API Scanner Bot GUI.

Displays detailed scan results including cookies, local/session storage,
and all captured network requests in organized treeview tables.
"""

import json
import tkinter as tk
from tkinter import ttk
from typing import Optional

from api_scanner.scanner.models import ScanResult


class ResultsTab(ttk.Frame):
    """Results tab displaying detailed scan data.

    Contains treeviews for cookies and network requests, plus text
    widgets for localStorage and sessionStorage data.

    Attributes:
        last_result: The most recent scan result being displayed.
    """

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        """Initialize the ResultsTab.

        Args:
            parent: Parent widget.
            **kwargs: Additional keyword arguments for ttk.Frame.
        """
        super().__init__(parent, **kwargs)
        self.last_result: Optional[ScanResult] = None

        self._create_widgets()

    def _create_widgets(self) -> None:
        """Create and layout all widgets for the results tab."""
        # Notebook for sub-sections
        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Cookies tab
        cookies_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(cookies_frame, text="Cookies")

        columns = ("name", "domain", "value", "secure")
        self._cookies_tree = ttk.Treeview(
            cookies_frame, columns=columns, show="headings", height=10
        )
        self._cookies_tree.heading("name", text="Name")
        self._cookies_tree.heading("domain", text="Domain")
        self._cookies_tree.heading("value", text="Value")
        self._cookies_tree.heading("secure", text="Secure")
        self._cookies_tree.column("name", width=150)
        self._cookies_tree.column("domain", width=150)
        self._cookies_tree.column("value", width=300)
        self._cookies_tree.column("secure", width=60)

        cookies_scroll = ttk.Scrollbar(
            cookies_frame, orient=tk.VERTICAL, command=self._cookies_tree.yview
        )
        self._cookies_tree.configure(yscrollcommand=cookies_scroll.set)
        self._cookies_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cookies_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Storage tab
        storage_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(storage_frame, text="Storage")

        # Local Storage
        local_frame = ttk.LabelFrame(storage_frame, text="Local Storage", padding=5)
        local_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        self._local_storage_text = tk.Text(
            local_frame,
            height=8,
            font=("Consolas", 9),
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self._local_storage_text.pack(fill=tk.BOTH, expand=True)

        # Session Storage
        session_frame = ttk.LabelFrame(storage_frame, text="Session Storage", padding=5)
        session_frame.pack(fill=tk.BOTH, expand=True)

        self._session_storage_text = tk.Text(
            session_frame,
            height=8,
            font=("Consolas", 9),
            state=tk.DISABLED,
            wrap=tk.WORD,
        )
        self._session_storage_text.pack(fill=tk.BOTH, expand=True)

        # Network Requests tab
        requests_frame = ttk.Frame(self._notebook, padding=10)
        self._notebook.add(requests_frame, text="Network Requests")

        req_columns = ("url", "method", "status", "content_type")
        self._requests_tree = ttk.Treeview(
            requests_frame, columns=req_columns, show="headings", height=15
        )
        self._requests_tree.heading("url", text="URL")
        self._requests_tree.heading("method", text="Method")
        self._requests_tree.heading("status", text="Status")
        self._requests_tree.heading("content_type", text="Content-Type")
        self._requests_tree.column("url", width=400)
        self._requests_tree.column("method", width=70)
        self._requests_tree.column("status", width=60)
        self._requests_tree.column("content_type", width=150)

        req_scroll = ttk.Scrollbar(
            requests_frame, orient=tk.VERTICAL, command=self._requests_tree.yview
        )
        self._requests_tree.configure(yscrollcommand=req_scroll.set)
        self._requests_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        req_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def populate(self, scan_result: ScanResult) -> None:
        """Populate all result views with scan data.

        Args:
            scan_result: The scan result to display.
        """
        self.last_result = scan_result
        self._populate_cookies(scan_result)
        self._populate_storage(scan_result)
        self._populate_requests(scan_result)

    def _populate_cookies(self, scan_result: ScanResult) -> None:
        """Populate the cookies treeview.

        Args:
            scan_result: The scan result containing cookie data.
        """
        for item in self._cookies_tree.get_children():
            self._cookies_tree.delete(item)

        if scan_result.storage_data and scan_result.storage_data.cookies:
            for cookie in scan_result.storage_data.cookies:
                self._cookies_tree.insert(
                    "",
                    tk.END,
                    values=(
                        cookie.name,
                        cookie.domain,
                        cookie.value[:100],
                        "Yes" if cookie.secure else "No",
                    ),
                )

    def _populate_storage(self, scan_result: ScanResult) -> None:
        """Populate the storage text widgets.

        Args:
            scan_result: The scan result containing storage data.
        """
        # Local Storage
        self._local_storage_text.configure(state=tk.NORMAL)
        self._local_storage_text.delete("1.0", tk.END)
        if scan_result.storage_data and scan_result.storage_data.local_storage:
            text = json.dumps(
                scan_result.storage_data.local_storage, indent=2, ensure_ascii=False
            )
            self._local_storage_text.insert("1.0", text)
        else:
            self._local_storage_text.insert("1.0", "No local storage data captured.")
        self._local_storage_text.configure(state=tk.DISABLED)

        # Session Storage
        self._session_storage_text.configure(state=tk.NORMAL)
        self._session_storage_text.delete("1.0", tk.END)
        if scan_result.storage_data and scan_result.storage_data.session_storage:
            text = json.dumps(
                scan_result.storage_data.session_storage, indent=2, ensure_ascii=False
            )
            self._session_storage_text.insert("1.0", text)
        else:
            self._session_storage_text.insert("1.0", "No session storage data captured.")
        self._session_storage_text.configure(state=tk.DISABLED)

    def _populate_requests(self, scan_result: ScanResult) -> None:
        """Populate the network requests treeview.

        Args:
            scan_result: The scan result containing request/response data.
        """
        for item in self._requests_tree.get_children():
            self._requests_tree.delete(item)

        for req in scan_result.requests:
            # Find matching response
            status = ""
            content_type = ""
            for resp in scan_result.responses:
                if resp.url == req.url:
                    status = str(resp.status_code)
                    content_type = resp.content_type
                    break

            self._requests_tree.insert(
                "",
                tk.END,
                values=(req.url, req.method, status, content_type),
            )
