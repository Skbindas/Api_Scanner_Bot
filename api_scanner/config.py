"""
Configuration management for the API Scanner Bot.

Provides a dataclass-based configuration system that loads settings from
environment variables and .env files using python-dotenv.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


@dataclass
class AppConfig:
    """Application configuration loaded from environment variables.

    Attributes:
        shodan_api_key: Shodan API key for security scanning.
        scan_timeout: Maximum time in seconds to wait for a scan response.
        max_retries: Number of times to retry failed requests.
        rate_limit_delay: Minimum delay in seconds between requests.
        output_dir: Directory for storing scan results.
        headless: Whether to run browser in headless mode.
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """

    shodan_api_key: str = ""
    scan_timeout: int = 30
    max_retries: int = 3
    rate_limit_delay: float = 1.0
    output_dir: str = "scan_results"
    headless: bool = True
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        """Load configuration from environment and validate."""
        self._load_from_env()
        self._validate()

    def _load_from_env(self) -> None:
        """Load configuration values from .env file and environment variables."""
        # Load .env file if it exists
        env_path = Path(".env")
        if env_path.exists():
            load_dotenv(env_path)

        # Override defaults with environment variables if set
        env_key = os.getenv("SHODAN_API_KEY")
        if env_key is not None:
            self.shodan_api_key = env_key

        env_timeout = os.getenv("SCAN_TIMEOUT")
        if env_timeout is not None:
            self.scan_timeout = int(env_timeout)

        env_retries = os.getenv("MAX_RETRIES")
        if env_retries is not None:
            self.max_retries = int(env_retries)

        env_rate_limit = os.getenv("RATE_LIMIT_DELAY")
        if env_rate_limit is not None:
            self.rate_limit_delay = float(env_rate_limit)

        env_output_dir = os.getenv("OUTPUT_DIR")
        if env_output_dir is not None:
            self.output_dir = env_output_dir

        env_headless = os.getenv("HEADLESS")
        if env_headless is not None:
            self.headless = env_headless.lower() in ("true", "1", "yes")

        env_log_level = os.getenv("LOG_LEVEL")
        if env_log_level is not None:
            self.log_level = env_log_level.upper()

    def _validate(self) -> None:
        """Validate configuration values.

        Raises:
            ValueError: If any configuration value is invalid.
        """
        if self.scan_timeout <= 0:
            raise ValueError("scan_timeout must be a positive integer")

        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")

        if self.rate_limit_delay < 0:
            raise ValueError("rate_limit_delay must be non-negative")

        valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level not in valid_log_levels:
            raise ValueError(
                f"log_level must be one of {valid_log_levels}, got '{self.log_level}'"
            )

        if not self.output_dir:
            raise ValueError("output_dir must not be empty")
