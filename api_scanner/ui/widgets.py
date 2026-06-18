"""
Custom Tkinter widgets for the API Scanner Bot UI.

Provides reusable widget components with professional styling:
StatusBar, URLInput, LogConsole, and RiskBadge.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import Optional

from api_scanner.utils import validate_url


class StatusBar(ttk.Frame):
    """Status bar widget showing current application status.

    Displays a text label indicating the current operation status
    and optionally shows progress information.

    Attributes:
        status_var: StringVar controlling the status text.
    """

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        """Initialize the StatusBar.

        Args:
            parent: Parent widget.
            **kwargs: Additional keyword arguments for ttk.Frame.
        """
        super().__init__(parent, **kwargs)

        self.status_var = tk.StringVar(value="Ready")

        self._label = ttk.Label(
            self,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=(5, 2),
        )
        self._label.pack(fill=tk.X, expand=True)

    def set_status(self, text: str) -> None:
        """Update the status bar text.

        Args:
            text: The new status text to display.
        """
        self.status_var.set(text)

    def set_progress(self, text: str) -> None:
        """Update status with a progress indicator prefix.

        Args:
            text: The progress text to display.
        """
        self.status_var.set(f"[Working] {text}")


class URLInput(ttk.Frame):
    """URL input widget with validation indicator.

    Provides a text entry field for URLs with a validate button
    and a green/red indicator showing whether the URL is valid.

    Attributes:
        url_var: StringVar containing the current URL text.
    """

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        """Initialize the URLInput widget.

        Args:
            parent: Parent widget.
            **kwargs: Additional keyword arguments for ttk.Frame.
        """
        super().__init__(parent, **kwargs)

        self.url_var = tk.StringVar()

        # URL entry field
        self._entry = ttk.Entry(self, textvariable=self.url_var, width=60)
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        # Validate button
        self._validate_btn = ttk.Button(
            self, text="Validate", command=self._validate, width=10
        )
        self._validate_btn.pack(side=tk.LEFT, padx=(0, 5))

        # Status indicator label
        self._indicator = ttk.Label(self, text="", width=3)
        self._indicator.pack(side=tk.LEFT)

    def _validate(self) -> None:
        """Validate the current URL and update the indicator."""
        url = self.url_var.get().strip()
        if validate_url(url):
            self._indicator.configure(text="\u2713", foreground="green")
        else:
            self._indicator.configure(text="\u2717", foreground="red")

    def get_url(self) -> str:
        """Get the current URL value.

        Returns:
            The URL string from the entry field.
        """
        return self.url_var.get().strip()

    def is_valid(self) -> bool:
        """Check if the current URL is valid.

        Returns:
            True if the URL passes validation, False otherwise.
        """
        return validate_url(self.url_var.get().strip())


class LogConsole(ttk.Frame):
    """Scrolled text console with colored log output.

    Provides a read-only scrolled text widget with tag-based coloring
    for different log levels (info, warning, error, success).

    The widget supports automatic scrolling to the latest entry.
    """

    def __init__(
        self, parent: tk.Widget, height: int = 10, **kwargs: object
    ) -> None:
        """Initialize the LogConsole.

        Args:
            parent: Parent widget.
            height: Number of visible text lines.
            **kwargs: Additional keyword arguments for ttk.Frame.
        """
        super().__init__(parent, **kwargs)

        self._text = scrolledtext.ScrolledText(
            self,
            height=height,
            state=tk.DISABLED,
            font=("Consolas", 9),
            background="#1e1e1e",
            foreground="#d4d4d4",
            insertbackground="#d4d4d4",
            wrap=tk.WORD,
        )
        self._text.pack(fill=tk.BOTH, expand=True)

        # Configure tags for colored output
        self._text.tag_configure("info", foreground="#d4d4d4")
        self._text.tag_configure("warning", foreground="#e5c07b")
        self._text.tag_configure("error", foreground="#e06c75")
        self._text.tag_configure("success", foreground="#98c379")
        self._text.tag_configure("timestamp", foreground="#7f848e")

    def log(self, message: str, level: str = "info") -> None:
        """Append a log message with the specified level color.

        Args:
            message: The message text to append.
            level: Log level for coloring (info, warning, error, success).
        """
        from datetime import datetime

        timestamp = datetime.now().strftime("%H:%M:%S")

        self._text.configure(state=tk.NORMAL)
        self._text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        self._text.insert(tk.END, f"{message}\n", level)
        self._text.configure(state=tk.DISABLED)
        self._text.see(tk.END)

    def clear(self) -> None:
        """Clear all text from the console."""
        self._text.configure(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.configure(state=tk.DISABLED)


class RiskBadge(ttk.Label):
    """Colored label widget showing a risk level.

    Displays a risk level (safe, low, medium, high, critical) with
    appropriate background coloring for visual indication.
    """

    # Color mapping for risk levels
    COLORS: dict[str, dict[str, str]] = {
        "safe": {"bg": "#dcfce7", "fg": "#166534"},
        "low": {"bg": "#dbeafe", "fg": "#1e40af"},
        "medium": {"bg": "#fef3c7", "fg": "#92400e"},
        "high": {"bg": "#fed7aa", "fg": "#9a3412"},
        "critical": {"bg": "#fecaca", "fg": "#991b1b"},
    }

    def __init__(self, parent: tk.Widget, **kwargs: object) -> None:
        """Initialize the RiskBadge.

        Args:
            parent: Parent widget.
            **kwargs: Additional keyword arguments for ttk.Label.
        """
        super().__init__(parent, **kwargs)
        self.set_risk("safe")

    def set_risk(self, level: str) -> None:
        """Update the displayed risk level with appropriate colors.

        Args:
            level: The risk level to display (safe, low, medium, high, critical).
        """
        level_lower = level.lower()
        colors = self.COLORS.get(level_lower, self.COLORS["safe"])

        self.configure(
            text=f" {level.upper()} ",
            background=colors["bg"],
            foreground=colors["fg"],
            font=("Segoe UI", 9, "bold"),
            padding=(8, 4),
        )
