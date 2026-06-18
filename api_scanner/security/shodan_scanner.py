"""
Shodan integration for the API Scanner Bot.

Provides a ShodanScanner class that queries the Shodan API for
host information, open ports, vulnerabilities, and service details.
"""

import asyncio
import socket
from typing import Optional

import shodan

from api_scanner.config import AppConfig
from api_scanner.exceptions import APIKeyError, NetworkError
from api_scanner.logger import setup_logger
from api_scanner.security.models import (
    SecurityFinding,
    ServiceInfo,
    VulnerabilityInfo,
)
from api_scanner.utils import retry_with_backoff


class ShodanScanner:
    """Queries the Shodan API for host security information.

    Resolves domains to IP addresses, then uses the Shodan host API
    to retrieve open ports, running services, and known vulnerabilities.

    Attributes:
        config: Application configuration with API key and timeout settings.
    """

    def __init__(self, config: AppConfig) -> None:
        """Initialize the Shodan scanner.

        Args:
            config: Application configuration containing the Shodan API key.
        """
        self.config = config
        self._api = shodan.Shodan(config.shodan_api_key)
        self._logger = setup_logger(__name__, config.log_level)

    def _validate_api_key(self) -> None:
        """Validate that a usable API key is configured.

        Raises:
            APIKeyError: If the API key is empty, None, or a placeholder.
        """
        key = self.config.shodan_api_key
        if not key or key.strip() == "":
            raise APIKeyError(
                "Shodan API key is not configured. "
                "Set SHODAN_API_KEY in your .env file or environment."
            )
        # Check for common placeholder values
        placeholders = {"your_api_key_here", "changeme", "xxx", "test"}
        if key.strip().lower() in placeholders:
            raise APIKeyError(
                "Shodan API key appears to be a placeholder value. "
                "Please set a valid API key."
            )

    def _resolve_domain(self, domain: str) -> str:
        """Resolve a domain name to an IP address.

        Args:
            domain: The domain name to resolve.

        Returns:
            The resolved IP address string.

        Raises:
            NetworkError: If DNS resolution fails.
        """
        try:
            ip = socket.gethostbyname(domain)
            self._logger.debug(f"Resolved {domain} to {ip}")
            return ip
        except socket.gaierror as e:
            raise NetworkError(
                f"Failed to resolve domain '{domain}': {e}"
            )

    @retry_with_backoff(max_attempts=3, min_wait=1.0, max_wait=30.0, retry_on=(NetworkError,))
    def _query_host(self, ip: str) -> dict:
        """Query Shodan for host information with retry logic.

        Args:
            ip: The IP address to query.

        Returns:
            Dictionary with Shodan host data.

        Raises:
            APIKeyError: If the API key is invalid or expired.
            NetworkError: If the query fails due to network issues.
        """
        try:
            return self._api.host(ip)
        except shodan.APIError as e:
            error_msg = str(e).lower()
            if "invalid api key" in error_msg or "access denied" in error_msg:
                raise APIKeyError(
                    f"Shodan API key is invalid or expired: {e}"
                )
            if "no information available" in error_msg:
                self._logger.info(f"No Shodan data available for {ip}")
                return {}
            raise NetworkError(f"Shodan API error for {ip}: {e}")

    def _parse_host_data(self, ip: str, data: dict) -> Optional[SecurityFinding]:
        """Parse raw Shodan host data into a SecurityFinding.

        Args:
            ip: The queried IP address.
            data: Raw response from Shodan host API.

        Returns:
            SecurityFinding with parsed data, or None if data is empty.
        """
        if not data:
            return None

        # Extract basic info
        organization = data.get("org", "Unknown")
        country = data.get("country_name", "Unknown")
        open_ports = data.get("ports", [])
        last_update = data.get("last_update", "")

        # Extract vulnerabilities
        vulnerabilities: list[VulnerabilityInfo] = []
        vulns = data.get("vulns", [])
        if isinstance(vulns, list):
            for cve_id in vulns:
                vulnerabilities.append(
                    VulnerabilityInfo(
                        cve_id=cve_id,
                        severity="unknown",
                        description=f"Vulnerability {cve_id} detected by Shodan",
                    )
                )
        elif isinstance(vulns, dict):
            for cve_id, details in vulns.items():
                severity = "unknown"
                description = f"Vulnerability {cve_id} detected by Shodan"
                if isinstance(details, dict):
                    severity = details.get("cvss", "unknown")
                    description = details.get("summary", description)
                vulnerabilities.append(
                    VulnerabilityInfo(
                        cve_id=cve_id,
                        severity=str(severity),
                        description=description,
                    )
                )

        # Extract services
        services: list[ServiceInfo] = []
        for banner in data.get("data", []):
            if isinstance(banner, dict):
                services.append(
                    ServiceInfo(
                        port=banner.get("port", 0),
                        product=banner.get("product", "unknown"),
                        version=banner.get("version", ""),
                        protocol=banner.get("transport", "tcp"),
                    )
                )

        return SecurityFinding(
            ip=ip,
            organization=organization,
            country=country,
            open_ports=open_ports,
            vulnerabilities=vulnerabilities,
            services=services,
            last_update=last_update,
        )

    async def scan(self, domain: str) -> Optional[SecurityFinding]:
        """Scan a domain for security information via Shodan.

        Validates the API key, resolves the domain to an IP address,
        queries the Shodan API, and returns structured security findings.

        Args:
            domain: The domain name to scan (e.g., 'example.com').

        Returns:
            SecurityFinding with host data, or None if no data available.

        Raises:
            APIKeyError: If the Shodan API key is missing or invalid.
            NetworkError: If DNS resolution or API query fails.
        """
        self._validate_api_key()

        self._logger.info(f"Starting Shodan scan for domain: {domain}")

        # Resolve domain to IP
        ip = self._resolve_domain(domain)
        self._logger.info(f"Resolved {domain} to IP: {ip}")

        # Query Shodan API in a thread to avoid blocking the event loop
        try:
            data = await asyncio.to_thread(self._query_host, ip)
        except (APIKeyError, NetworkError):
            raise
        except Exception as e:
            raise NetworkError(
                f"Unexpected error querying Shodan for {domain}: {e}"
            )

        # Parse and return the findings
        finding = self._parse_host_data(ip, data)
        if finding:
            self._logger.info(
                f"Shodan scan complete for {domain}: "
                f"{len(finding.open_ports)} open ports, "
                f"{len(finding.vulnerabilities)} vulnerabilities"
            )
        else:
            self._logger.info(f"No Shodan data available for {domain} ({ip})")

        return finding
