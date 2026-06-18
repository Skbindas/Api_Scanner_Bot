"""
Shared test fixtures for the API Scanner Bot test suite.
"""

import os
from unittest.mock import patch

import pytest

from api_scanner.config import AppConfig


@pytest.fixture
def app_config() -> AppConfig:
    """Create an AppConfig instance with test defaults.

    Returns:
        AppConfig instance with default values (environment variables cleared).
    """
    with patch.dict(os.environ, {}, clear=True):
        # Remove SHODAN_API_KEY if set so defaults are used
        env = {
            "SHODAN_API_KEY": "test_key_123",
            "SCAN_TIMEOUT": "30",
            "MAX_RETRIES": "3",
            "RATE_LIMIT_DELAY": "1.0",
            "OUTPUT_DIR": "scan_results",
            "HEADLESS": "true",
            "LOG_LEVEL": "INFO",
        }
        with patch.dict(os.environ, env):
            config = AppConfig()
    return config


@pytest.fixture
def temp_output_dir(tmp_path: os.PathLike) -> str:
    """Provide a temporary directory for scan output.

    Args:
        tmp_path: pytest built-in temporary path fixture.

    Returns:
        String path to a temporary output directory.
    """
    output_dir = str(tmp_path / "scan_results")
    return output_dir
