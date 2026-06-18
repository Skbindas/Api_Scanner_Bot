"""
Tests for the AppConfig configuration management module.
"""

import os
from unittest.mock import patch

import pytest

from api_scanner.config import AppConfig


class TestAppConfig:
    """Tests for AppConfig dataclass configuration loading."""

    def test_default_config(self, monkeypatch, tmp_path):
        """AppConfig creates with all defaults when no env vars are set."""
        # Change to a dir without .env so it doesn't get loaded
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        monkeypatch.delenv("SCAN_TIMEOUT", raising=False)
        monkeypatch.delenv("MAX_RETRIES", raising=False)
        monkeypatch.delenv("RATE_LIMIT_DELAY", raising=False)
        monkeypatch.delenv("OUTPUT_DIR", raising=False)
        monkeypatch.delenv("HEADLESS", raising=False)
        monkeypatch.delenv("LOG_LEVEL", raising=False)

        config = AppConfig()

        assert config.scan_timeout == 30
        assert config.max_retries == 3
        assert config.rate_limit_delay == 1.0
        assert config.headless is True
        assert config.shodan_api_key == ""

    def test_config_from_env(self, monkeypatch):
        """AppConfig picks up values from environment variables."""
        monkeypatch.setenv("SHODAN_API_KEY", "test_api_key_xyz")
        monkeypatch.setenv("SCAN_TIMEOUT", "60")
        monkeypatch.setenv("MAX_RETRIES", "5")
        monkeypatch.setenv("RATE_LIMIT_DELAY", "2.5")
        monkeypatch.setenv("OUTPUT_DIR", "custom_output")
        monkeypatch.setenv("HEADLESS", "false")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")

        config = AppConfig()

        assert config.shodan_api_key == "test_api_key_xyz"
        assert config.scan_timeout == 60
        assert config.max_retries == 5
        assert config.rate_limit_delay == 2.5
        assert config.output_dir == "custom_output"
        assert config.headless is False
        assert config.log_level == "DEBUG"

    def test_config_output_dir_default(self, monkeypatch, tmp_path):
        """Default output_dir is 'scan_results'."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("OUTPUT_DIR", raising=False)
        config = AppConfig()

        assert config.output_dir == "scan_results"

    def test_config_log_level_default(self, monkeypatch, tmp_path):
        """Default log_level is 'INFO'."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        config = AppConfig()

        assert config.log_level == "INFO"
