"""
Tests for the utility functions and classes module.
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from api_scanner.utils import (
    RateLimiter,
    ensure_directories,
    safe_json_serialize,
    validate_url,
)


class TestValidateUrl:
    """Tests for the validate_url function."""

    def test_validate_url_valid_https(self):
        """validate_url accepts a valid HTTPS URL."""
        assert validate_url("https://example.com") is True

    def test_validate_url_valid_http(self):
        """validate_url accepts a valid HTTP URL with path."""
        assert validate_url("http://test.org/path") is True

    def test_validate_url_invalid_no_scheme(self):
        """validate_url rejects a URL without a scheme."""
        assert validate_url("example.com") is False

    def test_validate_url_invalid_empty(self):
        """validate_url rejects an empty string."""
        assert validate_url("") is False

    def test_validate_url_invalid_text(self):
        """validate_url rejects plain text that is not a URL."""
        assert validate_url("not a url") is False


class TestSafeJsonSerialize:
    """Tests for the safe_json_serialize function."""

    def test_safe_json_serialize_bytes(self):
        """safe_json_serialize handles bytes objects by decoding them."""
        data = {"content": b"hello world"}
        result = safe_json_serialize(data)
        parsed = json.loads(result)
        assert parsed["content"] == "hello world"

    def test_safe_json_serialize_datetime(self):
        """safe_json_serialize handles datetime objects as ISO format strings."""
        dt = datetime(2024, 1, 15, 10, 30, 0)
        data = {"timestamp": dt}
        result = safe_json_serialize(data)
        parsed = json.loads(result)
        assert parsed["timestamp"] == "2024-01-15T10:30:00"

    def test_safe_json_serialize_dict(self):
        """safe_json_serialize handles normal dicts without modification."""
        data = {"key": "value", "number": 42, "nested": {"inner": True}}
        result = safe_json_serialize(data)
        parsed = json.loads(result)
        assert parsed == data


class TestRateLimiter:
    """Tests for the RateLimiter class."""

    def test_rate_limiter_allows(self):
        """RateLimiter with capacity allows immediate acquire."""
        limiter = RateLimiter(rate=10, capacity=10)
        # Should not block since capacity is 10
        limiter.acquire()
        # If we get here without blocking forever, the test passes
        assert True

    def test_rate_limiter_try_acquire(self):
        """RateLimiter try_acquire returns True when tokens available."""
        limiter = RateLimiter(rate=10, capacity=5)
        assert limiter.try_acquire() is True


class TestEnsureDirectories:
    """Tests for the ensure_directories function."""

    def test_ensure_directories(self, tmp_path):
        """ensure_directories creates expected subdirectories."""
        base = str(tmp_path / "output")
        ensure_directories(base)

        base_path = Path(base)
        assert base_path.exists()
        assert (base_path / "reports").exists()
        assert (base_path / "raw_data").exists()
        assert (base_path / "exports").exists()
        assert (base_path / "screenshots").exists()
