"""
Data models for the scanning engine.

Provides typed dataclasses representing the various data structures
captured during a scan, including requests, responses, cookies,
storage data, metadata, and aggregate scan results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class RequestData:
    """Represents an HTTP request captured during scanning.

    Attributes:
        url: The full URL of the request.
        method: HTTP method (GET, POST, PUT, etc.).
        headers: Dictionary of request headers.
        payload: Optional request body/payload content.
        timestamp: When the request was captured.
    """

    url: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    payload: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ResponseData:
    """Represents an HTTP response captured during scanning.

    Attributes:
        url: The URL that generated this response.
        status_code: HTTP status code of the response.
        headers: Dictionary of response headers.
        body_preview: First 500 characters of the response body.
        content_type: Content-Type header value.
        size: Size of the response body in bytes.
    """

    url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body_preview: str = ""
    content_type: str = ""
    size: int = 0


@dataclass
class CookieData:
    """Represents a browser cookie.

    Attributes:
        name: Cookie name.
        value: Cookie value.
        domain: Domain the cookie belongs to.
        path: URL path the cookie is valid for.
        secure: Whether the cookie requires HTTPS.
        http_only: Whether the cookie is HTTP-only (not accessible via JS).
        expires: Optional expiration date string.
    """

    name: str
    value: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    expires: Optional[str] = None


@dataclass
class StorageData:
    """Represents browser storage data extracted from a page.

    Attributes:
        local_storage: Key-value pairs from localStorage.
        session_storage: Key-value pairs from sessionStorage.
        cookies: List of cookies from the browser context.
    """

    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    cookies: list[CookieData] = field(default_factory=list)


@dataclass
class MetaData:
    """Represents metadata extracted from an HTML page.

    Attributes:
        title: Page title from the <title> tag.
        description: Meta description content.
        meta_tags: Dictionary of all meta tag name-content pairs.
        og_tags: Dictionary of Open Graph (og:) tag property-content pairs.
        security_headers: Dictionary of security-related HTTP headers.
    """

    title: str = ""
    description: str = ""
    meta_tags: dict[str, str] = field(default_factory=dict)
    og_tags: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Aggregate result of a complete URL scan.

    Contains all data captured during the scanning process, including
    network activity, detected API endpoints, storage data, and metadata.

    Attributes:
        url: The target URL that was scanned.
        requests: All HTTP requests captured during the scan.
        responses: All HTTP responses captured during the scan.
        api_endpoints: Requests identified as API endpoint calls.
        storage_data: Browser storage data (localStorage, sessionStorage, cookies).
        meta_data: HTML metadata and security headers.
        scan_duration: Total scan time in seconds.
        errors: List of error messages encountered during scanning.
        timestamp: When the scan was initiated.
    """

    url: str
    requests: list[RequestData] = field(default_factory=list)
    responses: list[ResponseData] = field(default_factory=list)
    api_endpoints: list[RequestData] = field(default_factory=list)
    storage_data: Optional[StorageData] = None
    meta_data: Optional[MetaData] = None
    scan_duration: float = 0.0
    errors: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
