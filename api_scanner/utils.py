"""
Utility functions and classes for the API Scanner Bot.

Provides common functionality used throughout the application including
URL validation, directory management, rate limiting, retry logic, and
safe serialization.
"""

import json
import os
import time
import threading
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar
from urllib.parse import urlparse

import tldextract
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

F = TypeVar("F", bound=Callable[..., Any])


def validate_url(url: str) -> bool:
    """Validate whether a string is a properly formatted URL.

    Checks both the URL structure using urllib.parse and the domain
    validity using tldextract.

    Args:
        url: The string to validate as a URL.

    Returns:
        True if the URL is valid, False otherwise.
    """
    if not url or not isinstance(url, str):
        return False

    try:
        parsed = urlparse(url)

        # Must have a valid scheme
        if parsed.scheme not in ("http", "https"):
            return False

        # Must have a netloc (host)
        if not parsed.netloc:
            return False

        # Use tldextract to validate the domain
        extracted = tldextract.extract(url)

        # Must have a valid domain and suffix (TLD)
        if not extracted.domain or not extracted.suffix:
            return False

        return True

    except (ValueError, TypeError):
        return False


def ensure_directories(base_path: str) -> None:
    """Create the scan results directory structure.

    Creates the base output directory and standard subdirectories
    for organizing scan results.

    Args:
        base_path: The base directory path for scan results.
    """
    base = Path(base_path)
    subdirs = ["reports", "raw_data", "exports", "screenshots"]

    base.mkdir(parents=True, exist_ok=True)

    for subdir in subdirs:
        (base / subdir).mkdir(parents=True, exist_ok=True)


class RateLimiter:
    """Token bucket rate limiter for controlling request frequency.

    Implements a token bucket algorithm that allows bursts up to the
    bucket capacity while maintaining a sustainable average rate.

    Attributes:
        rate: Tokens added per second.
        capacity: Maximum number of tokens in the bucket.
    """

    def __init__(self, rate: float = 1.0, capacity: int = 10) -> None:
        """Initialize the rate limiter.

        Args:
            rate: Number of tokens to add per second.
            capacity: Maximum tokens the bucket can hold.
        """
        self.rate = rate
        self.capacity = capacity
        self._tokens: float = float(capacity)
        self._last_refill: float = time.time()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, blocking until they are available.

        Args:
            tokens: Number of tokens to acquire.
        """
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
            # Wait a short time before retrying
            time.sleep(0.01)

    def try_acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens without blocking.

        Args:
            tokens: Number of tokens to acquire.

        Returns:
            True if tokens were acquired, False otherwise.
        """
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


def retry_with_backoff(
    max_attempts: int = 3,
    min_wait: float = 1.0,
    max_wait: float = 60.0,
    retry_on: type = Exception,
) -> Callable[[F], F]:
    """Create a retry decorator with exponential backoff.

    Uses the tenacity library for robust retry logic with configurable
    exponential backoff.

    Args:
        max_attempts: Maximum number of attempts before giving up.
        min_wait: Minimum wait time in seconds between retries.
        max_wait: Maximum wait time in seconds between retries.
        retry_on: Exception type(s) to retry on.

    Returns:
        Decorator function that adds retry logic to the wrapped function.
    """

    def decorator(func: F) -> F:
        """Apply retry logic to the decorated function."""
        @retry(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(multiplier=min_wait, max=max_wait),
            retry=retry_if_exception_type(retry_on),
            reraise=True,
        )
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator  # type: ignore[return-value]


def safe_json_serialize(obj: Any) -> str:
    """Serialize an object to JSON, handling non-standard types.

    Handles bytes, datetime objects, sets, and other types that the
    standard JSON encoder cannot process.

    Args:
        obj: The object to serialize.

    Returns:
        JSON string representation of the object.
    """

    def default_handler(o: Any) -> Any:
        """Handle non-serializable types."""
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="replace")
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, set):
            return list(o)
        if isinstance(o, Path):
            return str(o)
        raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")

    return json.dumps(obj, default=default_handler, indent=2, ensure_ascii=False)
