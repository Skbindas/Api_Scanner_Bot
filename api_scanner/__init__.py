"""
API Scanner Bot - Professional API Security Scanner.

A comprehensive tool for scanning, analyzing, and reporting on API endpoints
with integrated security assessment capabilities.
"""

__version__ = "2.0.0"
__author__ = "Suhaib Choudhary"

from api_scanner.config import AppConfig
from api_scanner.exceptions import (
    ScannerError,
    NetworkError,
    TimeoutError,
    APIKeyError,
    ValidationError,
    ExportError,
    BrowserError,
)
from api_scanner.logger import setup_logger

__all__ = [
    "AppConfig",
    "ScannerError",
    "NetworkError",
    "TimeoutError",
    "APIKeyError",
    "ValidationError",
    "ExportError",
    "BrowserError",
    "setup_logger",
    "__version__",
]
