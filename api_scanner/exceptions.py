"""
Custom exception hierarchy for the API Scanner Bot.

All scanner-specific exceptions inherit from ScannerError, providing
a consistent error handling pattern throughout the application.
"""


class ScannerError(Exception):
    """Base exception for all API Scanner errors.

    All custom exceptions in the scanner inherit from this class,
    allowing callers to catch all scanner-related errors with a
    single except clause.
    """

    def __init__(self, message: str = "", *args: object) -> None:
        """Initialize ScannerError.

        Args:
            message: Human-readable error description.
            *args: Additional arguments passed to Exception.
        """
        self.message = message
        super().__init__(message, *args)


class NetworkError(ScannerError):
    """Raised when a network operation fails.

    Examples include connection timeouts, DNS resolution failures,
    and unreachable hosts.
    """

    pass


class TimeoutError(ScannerError):
    """Raised when an operation exceeds its time limit.

    This is distinct from network timeouts - it covers any operation
    that takes longer than the configured scan_timeout.
    """

    pass


class APIKeyError(ScannerError):
    """Raised when an API key is missing, invalid, or expired.

    This covers authentication failures with external services
    like Shodan.
    """

    pass


class ValidationError(ScannerError):
    """Raised when input validation fails.

    Examples include invalid URLs, malformed configuration values,
    and unsupported scan parameters.
    """

    pass


class ExportError(ScannerError):
    """Raised when exporting scan results fails.

    This covers failures in writing reports, generating PDFs,
    or saving data to files.
    """

    pass


class BrowserError(ScannerError):
    """Raised when browser automation encounters an error.

    This covers Playwright-related failures such as page load errors,
    element not found, and browser crashes.
    """

    pass
