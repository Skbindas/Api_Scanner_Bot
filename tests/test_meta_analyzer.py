"""
Tests for the MetaAnalyzer module.

Tests HTML metadata extraction including title, description, meta tags,
Open Graph tags, and security headers.
"""

import pytest

from api_scanner.scanner.meta_analyzer import MetaAnalyzer
from api_scanner.scanner.models import MetaData


@pytest.fixture
def analyzer() -> MetaAnalyzer:
    """Create a MetaAnalyzer instance for testing."""
    return MetaAnalyzer()


class TestMetaAnalyzerTitle:
    """Tests for page title extraction."""

    def test_extract_title(self, analyzer: MetaAnalyzer) -> None:
        html = "<html><head><title>Test Page</title></head><body></body></html>"
        result = analyzer.analyze(html)
        assert result.title == "Test Page"

    def test_extract_title_with_whitespace(self, analyzer: MetaAnalyzer) -> None:
        html = "<html><head><title>  Spaced Title  </title></head><body></body></html>"
        result = analyzer.analyze(html)
        assert result.title == "Spaced Title"

    def test_missing_title(self, analyzer: MetaAnalyzer) -> None:
        html = "<html><head></head><body></body></html>"
        result = analyzer.analyze(html)
        assert result.title == ""

    def test_empty_title(self, analyzer: MetaAnalyzer) -> None:
        html = "<html><head><title></title></head><body></body></html>"
        result = analyzer.analyze(html)
        assert result.title == ""


class TestMetaAnalyzerDescription:
    """Tests for meta description extraction."""

    def test_extract_description(self, analyzer: MetaAnalyzer) -> None:
        html = (
            '<html><head><meta name="description" content="A test page">'
            "</head><body></body></html>"
        )
        result = analyzer.analyze(html)
        assert result.description == "A test page"

    def test_missing_description(self, analyzer: MetaAnalyzer) -> None:
        html = "<html><head></head><body></body></html>"
        result = analyzer.analyze(html)
        assert result.description == ""

    def test_empty_description_content(self, analyzer: MetaAnalyzer) -> None:
        html = (
            '<html><head><meta name="description" content="">'
            "</head><body></body></html>"
        )
        result = analyzer.analyze(html)
        assert result.description == ""


class TestMetaAnalyzerMetaTags:
    """Tests for general meta tag extraction."""

    def test_extract_meta_tags(self, analyzer: MetaAnalyzer) -> None:
        html = (
            "<html><head>"
            '<meta name="author" content="John Doe">'
            '<meta name="keywords" content="test, demo">'
            "</head><body></body></html>"
        )
        result = analyzer.analyze(html)
        assert result.meta_tags["author"] == "John Doe"
        assert result.meta_tags["keywords"] == "test, demo"

    def test_extract_http_equiv_meta(self, analyzer: MetaAnalyzer) -> None:
        html = (
            "<html><head>"
            '<meta http-equiv="X-UA-Compatible" content="IE=edge">'
            "</head><body></body></html>"
        )
        result = analyzer.analyze(html)
        assert result.meta_tags["x-ua-compatible"] == "IE=edge"

    def test_meta_without_content_ignored(self, analyzer: MetaAnalyzer) -> None:
        html = (
            "<html><head>"
            '<meta name="viewport">'
            "</head><body></body></html>"
        )
        result = analyzer.analyze(html)
        assert "viewport" not in result.meta_tags

    def test_empty_html_no_meta(self, analyzer: MetaAnalyzer) -> None:
        html = "<html><head></head><body></body></html>"
        result = analyzer.analyze(html)
        assert result.meta_tags == {}


class TestMetaAnalyzerOGTags:
    """Tests for Open Graph tag extraction."""

    def test_extract_og_tags(self, analyzer: MetaAnalyzer) -> None:
        html = (
            "<html><head>"
            '<meta property="og:title" content="OG Title">'
            '<meta property="og:description" content="OG Desc">'
            '<meta property="og:image" content="https://example.com/img.png">'
            "</head><body></body></html>"
        )
        result = analyzer.analyze(html)
        assert result.og_tags["title"] == "OG Title"
        assert result.og_tags["description"] == "OG Desc"
        assert result.og_tags["image"] == "https://example.com/img.png"

    def test_non_og_property_ignored(self, analyzer: MetaAnalyzer) -> None:
        html = (
            "<html><head>"
            '<meta property="article:author" content="Jane">'
            "</head><body></body></html>"
        )
        result = analyzer.analyze(html)
        assert "author" not in result.og_tags

    def test_no_og_tags(self, analyzer: MetaAnalyzer) -> None:
        html = "<html><head></head><body></body></html>"
        result = analyzer.analyze(html)
        assert result.og_tags == {}


class TestMetaAnalyzerSecurityHeaders:
    """Tests for security header extraction."""

    def test_extract_security_headers(self, analyzer: MetaAnalyzer) -> None:
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Server": "nginx",
        }
        html = "<html><head><title>Test</title></head><body></body></html>"
        result = analyzer.analyze(html, response_headers=headers)
        assert result.security_headers["Content-Security-Policy"] == "default-src 'self'"
        assert result.security_headers["X-Frame-Options"] == "DENY"
        assert result.security_headers["X-Content-Type-Options"] == "nosniff"
        # Non-security headers should not be included
        assert "Server" not in result.security_headers

    def test_case_insensitive_header_matching(self, analyzer: MetaAnalyzer) -> None:
        headers = {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "SAMEORIGIN",
        }
        html = "<html><head></head><body></body></html>"
        result = analyzer.analyze(html, response_headers=headers)
        assert result.security_headers["Content-Security-Policy"] == "default-src 'self'"
        assert result.security_headers["X-Frame-Options"] == "SAMEORIGIN"

    def test_no_response_headers(self, analyzer: MetaAnalyzer) -> None:
        html = "<html><head></head><body></body></html>"
        result = analyzer.analyze(html, response_headers=None)
        assert result.security_headers == {}

    def test_empty_response_headers(self, analyzer: MetaAnalyzer) -> None:
        html = "<html><head></head><body></body></html>"
        result = analyzer.analyze(html, response_headers={})
        assert result.security_headers == {}


class TestMetaAnalyzerFullPage:
    """Integration tests with realistic HTML content."""

    def test_full_page_analysis(self, analyzer: MetaAnalyzer) -> None:
        html = """<!DOCTYPE html>
        <html>
        <head>
            <title>My Website</title>
            <meta name="description" content="Welcome to my website">
            <meta name="author" content="Developer">
            <meta name="robots" content="index, follow">
            <meta property="og:title" content="My Website - Social">
            <meta property="og:type" content="website">
            <meta property="og:url" content="https://example.com">
        </head>
        <body>
            <h1>Hello World</h1>
        </body>
        </html>
        """
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "no-referrer",
        }
        result = analyzer.analyze(html, response_headers=headers)

        assert result.title == "My Website"
        assert result.description == "Welcome to my website"
        assert result.meta_tags["author"] == "Developer"
        assert result.meta_tags["robots"] == "index, follow"
        assert result.og_tags["title"] == "My Website - Social"
        assert result.og_tags["type"] == "website"
        assert result.og_tags["url"] == "https://example.com"
        assert result.security_headers["Strict-Transport-Security"] == "max-age=31536000"
        assert result.security_headers["Referrer-Policy"] == "no-referrer"
        assert isinstance(result, MetaData)
