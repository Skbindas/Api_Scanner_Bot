"""
Security data models for the API Scanner Bot.

Provides typed dataclasses for representing security findings,
threat indicators, and analysis reports.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class VulnerabilityInfo:
    """Information about a discovered vulnerability.

    Attributes:
        cve_id: The CVE identifier (e.g., CVE-2021-44228).
        severity: Severity level (low, medium, high, critical).
        description: Human-readable description of the vulnerability.
    """

    cve_id: str
    severity: str
    description: str


@dataclass
class ServiceInfo:
    """Information about a network service running on a host.

    Attributes:
        port: The port number the service is listening on.
        product: The software product name (e.g., Apache, nginx).
        version: The version string of the product.
        protocol: The network protocol (tcp, udp).
    """

    port: int
    product: str
    version: str
    protocol: str


@dataclass
class SecurityFinding:
    """Complete security finding for a scanned host.

    Aggregates all security-relevant information discovered about
    a target host including open ports, vulnerabilities, and services.

    Attributes:
        ip: The IP address of the scanned host.
        organization: The organization that owns the IP range.
        country: The country where the host is located.
        open_ports: List of open port numbers.
        vulnerabilities: List of discovered vulnerabilities.
        services: List of running services with version info.
        last_update: Timestamp of when Shodan last scanned this host.
    """

    ip: str
    organization: str
    country: str
    open_ports: List[int] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    last_update: str = ""


@dataclass
class ThreatIndicator:
    """A single threat indicator found during analysis.

    Represents one specific security concern identified by the
    threat analyzer's heuristic checks.

    Attributes:
        category: The type of threat (e.g., phishing, malware, suspicious).
        description: Human-readable explanation of the finding.
        severity: Severity level (low, medium, high, critical).
        evidence: The specific data that triggered this indicator.
    """

    category: str
    description: str
    severity: str
    evidence: str


@dataclass
class ThreatReport:
    """Complete threat analysis report for a URL or page.

    Aggregates all threat indicators and provides an overall
    risk assessment with scoring.

    Attributes:
        url: The analyzed URL.
        risk_score: Overall risk score from 0 (safe) to 100 (critical).
        risk_level: Human-readable risk level (safe, low, medium, high, critical).
        indicators: List of specific threat indicators found.
        summary: Brief summary of the analysis results.
        analyzed_at: Timestamp of when the analysis was performed.
    """

    url: str
    risk_score: int
    risk_level: str
    indicators: List[ThreatIndicator] = field(default_factory=list)
    summary: str = ""
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
