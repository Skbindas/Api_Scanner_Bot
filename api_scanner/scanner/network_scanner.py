"""
Network scanner module for capturing HTTP traffic via Playwright.

Provides the NetworkScanner class that uses Playwright to navigate to
a target URL, intercept all network requests and responses, and identify
API endpoints using multiple detection heuristics.
"""

import re
import time
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Page, Request, Response

from api_scanner.config import AppConfig
from api_scanner.exceptions import BrowserError, NetworkError, TimeoutError
from api_scanner.logger import setup_logger
from api_scanner.scanner.meta_analyzer import MetaAnalyzer
from api_scanner.scanner.models import (
    MetaData,
    RequestData,
    ResponseData,
    ScanResult,
    StorageData,
)
from api_scanner.scanner.storage_analyzer import StorageAnalyzer


class NetworkScanner:
    """Scans web pages using Playwright to capture network traffic.

    Uses a headless browser to navigate to target URLs, capturing all
    HTTP requests and responses. Identifies API endpoints using multiple
    heuristics including URL patterns and response content types.

    Attributes:
        config: Application configuration instance.
    """

    # URL patterns that indicate an API endpoint
    API_PATH_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"/api/", re.IGNORECASE),
        re.compile(r"/v[1-9]\d*/", re.IGNORECASE),
        re.compile(r"/graphql", re.IGNORECASE),
        re.compile(r"/rest/", re.IGNORECASE),
        re.compile(r"/ws/", re.IGNORECASE),
        re.compile(r"\.json$", re.IGNORECASE),
        re.compile(r"/rpc/", re.IGNORECASE),
        re.compile(r"/webhook", re.IGNORECASE),
        re.compile(r"/oauth", re.IGNORECASE),
        re.compile(r"/auth/", re.IGNORECASE),
    ]

    # Content types that indicate an API response
    API_CONTENT_TYPES: list[str] = [
        "application/json",
        "application/graphql",
        "application/xml",
        "text/xml",
        "application/grpc",
        "application/x-protobuf",
    ]

    # Maximum size of response body to capture (in bytes)
    MAX_BODY_PREVIEW_SIZE: int = 500

    def __init__(self, config: AppConfig) -> None:
        """Initialize the NetworkScanner with configuration.

        Args:
            config: AppConfig instance with scan settings.
        """
        self.config = config
        self._logger = setup_logger(__name__, level=config.log_level)
        self._storage_analyzer = StorageAnalyzer()
        self._meta_analyzer = MetaAnalyzer()
        self._captured_requests: list[RequestData] = []
        self._captured_responses: list[ResponseData] = []
        self._raw_responses: list[Response] = []

    async def scan(self, url: str) -> ScanResult:
        """Perform a full scan of the target URL.

        Launches a headless browser, navigates to the URL, captures all
        network traffic, extracts storage data and page metadata, and
        identifies API endpoints.

        Args:
            url: The target URL to scan.

        Returns:
            ScanResult containing all captured data from the scan.

        Raises:
            BrowserError: If the browser fails to launch or crashes.
            TimeoutError: If the page navigation exceeds the timeout.
            NetworkError: If a network-level error prevents scanning.
        """
        self._logger.info("Starting scan of URL: %s", url)
        start_time = time.time()

        # Reset captured data for this scan
        self._captured_requests = []
        self._captured_responses = []
        self._raw_responses = []
        errors: list[str] = []
        storage_data: Optional[StorageData] = None
        meta_data: Optional[MetaData] = None

        browser = None
        playwright_instance = None

        try:
            playwright_instance = await async_playwright().start()

            browser = await playwright_instance.chromium.launch(
                headless=self.config.headless
            )
            self._logger.debug("Browser launched (headless=%s)", self.config.headless)

            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            )

            page = await context.new_page()

            # Set up request/response interception
            page.on("request", self._on_request)
            page.on("response", self._on_response)

            # Navigate to the target URL
            self._logger.info("Navigating to %s", url)
            try:
                await page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=self.config.scan_timeout * 1000,
                )
            except Exception as e:
                error_msg = str(e)
                if "timeout" in error_msg.lower() or "Timeout" in error_msg:
                    raise TimeoutError(
                        f"Page navigation timed out after {self.config.scan_timeout}s: {url}"
                    ) from e
                if "net::" in error_msg.lower() or "ERR_" in error_msg:
                    raise NetworkError(
                        f"Network error navigating to {url}: {error_msg}"
                    ) from e
                raise BrowserError(
                    f"Browser error navigating to {url}: {error_msg}"
                ) from e

            self._logger.info(
                "Page loaded, captured %d requests and %d responses",
                len(self._captured_requests),
                len(self._captured_responses),
            )

            # Read response bodies now that we are in an async context
            await self._read_response_bodies()

            # Extract storage data
            try:
                storage_data = await self._storage_analyzer.analyze(page)
            except Exception as e:
                error_msg = f"Storage analysis failed: {str(e)}"
                self._logger.warning(error_msg)
                errors.append(error_msg)

            # Extract page metadata
            try:
                html_content = await page.content()
                # Get response headers from the main page response
                response_headers = self._get_main_response_headers(url)
                meta_data = self._meta_analyzer.analyze(html_content, response_headers)
            except Exception as e:
                error_msg = f"Metadata analysis failed: {str(e)}"
                self._logger.warning(error_msg)
                errors.append(error_msg)

            # Identify API endpoints
            api_endpoints = self._identify_api_endpoints()

            scan_duration = time.time() - start_time

            result = ScanResult(
                url=url,
                requests=list(self._captured_requests),
                responses=list(self._captured_responses),
                api_endpoints=api_endpoints,
                storage_data=storage_data,
                meta_data=meta_data,
                scan_duration=scan_duration,
                errors=errors,
                timestamp=datetime.now(),
            )

            self._logger.info(
                "Scan complete: %d requests, %d responses, %d API endpoints, "
                "duration=%.2fs",
                len(result.requests),
                len(result.responses),
                len(result.api_endpoints),
                scan_duration,
            )

            return result

        except (TimeoutError, NetworkError, BrowserError):
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            raise BrowserError(
                f"Unexpected error during scan of {url}: {str(e)}"
            ) from e
        finally:
            if browser:
                try:
                    await browser.close()
                    self._logger.debug("Browser closed")
                except Exception as e:
                    self._logger.warning("Error closing browser: %s", str(e))
            if playwright_instance:
                try:
                    await playwright_instance.stop()
                except Exception as e:
                    self._logger.warning("Error stopping playwright: %s", str(e))

    def _on_request(self, request: Request) -> None:
        """Handle intercepted network requests.

        Callback for Playwright's request event. Captures request data
        into the internal list.

        Args:
            request: The Playwright Request object.
        """
        try:
            request_data = RequestData(
                url=request.url,
                method=request.method,
                headers=dict(request.headers) if request.headers else {},
                payload=request.post_data if request.post_data else None,
                timestamp=datetime.now(),
            )
            self._captured_requests.append(request_data)
        except Exception as e:
            self._logger.debug("Error capturing request: %s", str(e))

    def _on_response(self, response: Response) -> None:
        """Handle intercepted network responses.

        Callback for Playwright's response event. Captures response metadata
        into the internal list and stores the raw Playwright Response object
        for later body reading in an async context.

        Args:
            response: The Playwright Response object.
        """
        try:
            # Get content type from headers
            headers = dict(response.headers) if response.headers else {}
            content_type = headers.get("content-type", "")

            response_data = ResponseData(
                url=response.url,
                status_code=response.status,
                headers=headers,
                body_preview="",  # Populated later in _read_response_bodies
                content_type=content_type,
                size=0,
            )
            self._captured_responses.append(response_data)
            # Keep the raw Playwright Response for body reading after navigation
            self._raw_responses.append(response)
        except Exception as e:
            self._logger.debug("Error capturing response: %s", str(e))

    async def _read_response_bodies(self) -> None:
        """Read response bodies from collected Playwright Response objects.

        Iterates through raw Response objects collected during page events
        and reads their bodies within this async context. Updates the
        corresponding ResponseData entries with body_preview and size.
        """
        for i, raw_response in enumerate(self._raw_responses):
            if i >= len(self._captured_responses):
                break
            try:
                body = await raw_response.body()
                size = len(body) if body else 0
                self._captured_responses[i].size = size
                if body:
                    decoded = self._decode_body(body)
                    self._captured_responses[i].body_preview = decoded[
                        : self.MAX_BODY_PREVIEW_SIZE
                    ]
            except Exception as e:
                self._logger.debug(
                    "Could not read body for %s: %s",
                    self._captured_responses[i].url,
                    str(e),
                )

    def _identify_api_endpoints(self) -> list[RequestData]:
        """Identify API endpoints from captured requests and responses.

        Uses multiple heuristics to determine which requests are likely
        API calls:
        - URL path patterns (/api/, /v1/, /graphql, /rest/, etc.)
        - JSON or API content-type in the response
        - .json file extension
        - WebSocket patterns

        Returns:
            List of RequestData objects identified as API endpoint calls.
        """
        api_endpoints: list[RequestData] = []
        seen_urls: set[str] = set()

        # Build a mapping of URL to response for content-type checking
        response_by_url: dict[str, ResponseData] = {}
        for resp in self._captured_responses:
            response_by_url[resp.url] = resp

        for request in self._captured_requests:
            # Skip duplicate URLs
            if request.url in seen_urls:
                continue

            if self._is_api_endpoint(request, response_by_url.get(request.url)):
                api_endpoints.append(request)
                seen_urls.add(request.url)

        self._logger.debug("Identified %d API endpoints", len(api_endpoints))
        return api_endpoints

    def _is_api_endpoint(
        self, request: RequestData, response: Optional[ResponseData] = None
    ) -> bool:
        """Determine if a request represents an API endpoint call.

        Applies multiple heuristics to identify API endpoints.

        Args:
            request: The captured request data.
            response: Optional corresponding response data.

        Returns:
            True if the request is likely an API endpoint call.
        """
        url = request.url
        parsed = urlparse(url)
        path = parsed.path

        # Skip common non-API resources
        static_extensions = (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
        )
        if any(path.lower().endswith(ext) for ext in static_extensions):
            return False

        # Check URL path patterns
        for pattern in self.API_PATH_PATTERNS:
            if pattern.search(path):
                return True

        # Check response content type
        if response and response.content_type:
            content_type_lower = response.content_type.lower()
            for api_content_type in self.API_CONTENT_TYPES:
                if api_content_type in content_type_lower:
                    return True

        # Check if request has JSON content type
        request_content_type = request.headers.get("content-type", "").lower()
        if "application/json" in request_content_type:
            return True

        # Check for non-GET methods (often indicate API calls)
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.payload:
            return True

        return False

    def _get_main_response_headers(self, url: str) -> dict[str, str]:
        """Get response headers for the main page request.

        Finds the response that matches the scanned URL to extract
        headers for security header analysis.

        Args:
            url: The target URL that was scanned.

        Returns:
            Dictionary of response headers, or empty dict if not found.
        """
        for response in self._captured_responses:
            if response.url == url or response.url.rstrip("/") == url.rstrip("/"):
                return response.headers
        return {}

    @staticmethod
    def _decode_body(body: bytes) -> str:
        """Safely decode response body bytes to a string.

        Attempts UTF-8 first, then falls back to latin-1, and finally
        uses repr() as a last resort.

        Args:
            body: Raw response body bytes.

        Returns:
            Decoded string representation of the body.
        """
        if not body:
            return ""

        try:
            return body.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            pass

        try:
            return body.decode("latin-1")
        except (UnicodeDecodeError, AttributeError):
            pass

        return repr(body)
