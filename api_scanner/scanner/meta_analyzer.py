"""
Meta analyzer for extracting HTML metadata and security headers.

Provides the MetaAnalyzer class which uses BeautifulSoup to parse HTML
content and extract page title, meta descriptions, Open Graph tags,
and security-related headers.
"""

from typing import Optional

from bs4 import BeautifulSoup

from api_scanner.logger import setup_logger
from api_scanner.scanner.models import MetaData


class MetaAnalyzer:
    """Analyzes HTML content to extract metadata and security information.

    Uses BeautifulSoup to parse HTML and extract structured metadata
    including page title, description, meta tags, Open Graph data,
    and security headers.
    """

    # Security headers to look for in response headers
    SECURITY_HEADERS: list[str] = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
    ]

    def __init__(self) -> None:
        """Initialize the MetaAnalyzer with a logger."""
        self._logger = setup_logger(__name__)

    def analyze(
        self,
        html_content: str,
        response_headers: Optional[dict[str, str]] = None,
    ) -> MetaData:
        """Extract metadata from HTML content.

        Parses the HTML to extract the page title, meta description,
        all meta tags, Open Graph tags, and security headers from
        the response.

        Args:
            html_content: The raw HTML content to parse.
            response_headers: Optional HTTP response headers to check
                for security headers.

        Returns:
            MetaData instance containing all extracted metadata.
        """
        self._logger.info("Analyzing page metadata")

        soup = BeautifulSoup(html_content, "lxml")

        title = self._extract_title(soup)
        description = self._extract_description(soup)
        meta_tags = self._extract_meta_tags(soup)
        og_tags = self._extract_og_tags(soup)
        security_headers = self._extract_security_headers(response_headers)

        meta_data = MetaData(
            title=title,
            description=description,
            meta_tags=meta_tags,
            og_tags=og_tags,
            security_headers=security_headers,
        )

        self._logger.info(
            "Metadata analysis complete: title='%s', %d meta tags, %d OG tags",
            title[:50] if title else "(none)",
            len(meta_tags),
            len(og_tags),
        )

        return meta_data

    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract the page title from the HTML.

        Args:
            soup: Parsed BeautifulSoup object.

        Returns:
            Page title string, or empty string if not found.
        """
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            return title_tag.string.strip()
        return ""

    def _extract_description(self, soup: BeautifulSoup) -> str:
        """Extract the meta description from the HTML.

        Args:
            soup: Parsed BeautifulSoup object.

        Returns:
            Meta description string, or empty string if not found.
        """
        desc_tag = soup.find("meta", attrs={"name": "description"})
        if desc_tag and desc_tag.get("content"):
            return str(desc_tag["content"]).strip()
        return ""

    def _extract_meta_tags(self, soup: BeautifulSoup) -> dict[str, str]:
        """Extract all meta tags with name and content attributes.

        Args:
            soup: Parsed BeautifulSoup object.

        Returns:
            Dictionary mapping meta tag names to their content values.
        """
        meta_tags: dict[str, str] = {}

        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("http-equiv")
            content = tag.get("content")

            if name and content:
                meta_tags[str(name).lower()] = str(content)

        return meta_tags

    def _extract_og_tags(self, soup: BeautifulSoup) -> dict[str, str]:
        """Extract Open Graph (og:) meta tags.

        Args:
            soup: Parsed BeautifulSoup object.

        Returns:
            Dictionary mapping OG property names to their content values.
        """
        og_tags: dict[str, str] = {}

        for tag in soup.find_all("meta", attrs={"property": True}):
            prop = str(tag.get("property", ""))
            content = tag.get("content")

            if prop.startswith("og:") and content:
                # Store without the 'og:' prefix for cleaner access
                key = prop[3:]
                og_tags[key] = str(content)

        return og_tags

    def _extract_security_headers(
        self, response_headers: Optional[dict[str, str]] = None
    ) -> dict[str, str]:
        """Extract security-related headers from the HTTP response.

        Checks for the presence of common security headers in the
        response headers dictionary.

        Args:
            response_headers: HTTP response headers dictionary.

        Returns:
            Dictionary of security header names and their values.
            Missing headers are not included.
        """
        if not response_headers:
            return {}

        security_headers: dict[str, str] = {}

        # Normalize header keys to lowercase for comparison
        normalized_headers = {k.lower(): v for k, v in response_headers.items()}

        for header in self.SECURITY_HEADERS:
            header_lower = header.lower()
            if header_lower in normalized_headers:
                security_headers[header] = normalized_headers[header_lower]

        return security_headers
