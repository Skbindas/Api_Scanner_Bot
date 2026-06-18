"""
Heuristic-based threat analyzer for the API Scanner Bot.

Provides comprehensive URL and HTML content analysis using rule-based
detection methods to identify phishing, malware, and other threats.
This replaces ML-based approaches with deterministic, explainable heuristics.
"""

import re
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup

from api_scanner.logger import setup_logger
from api_scanner.security.models import ThreatIndicator, ThreatReport


class ThreatAnalyzer:
    """Heuristic-based threat detection for URLs and web content.

    Uses a comprehensive set of pattern-matching rules to identify
    potential security threats without relying on machine learning.
    Each check produces a ThreatIndicator with severity scoring.
    """

    # Known phishing/suspicious TLDs
    SUSPICIOUS_TLDS: set = {
        "tk", "ml", "ga", "cf", "gq", "xyz", "top",
        "work", "click", "loan", "zip",
    }

    # Common brand names targeted by typosquatting
    TYPOSQUAT_PATTERNS: dict = {
        "googl": "google",
        "gogle": "google",
        "g00gle": "google",
        "faceb00k": "facebook",
        "facbook": "facebook",
        "facebok": "facebook",
        "paypa1": "paypal",
        "payp4l": "paypal",
        "paypol": "paypal",
        "amaz0n": "amazon",
        "amazn": "amazon",
        "amazonn": "amazon",
        "micros0ft": "microsoft",
        "mircosoft": "microsoft",
        "microsft": "microsoft",
        "appl3": "apple",
        "app1e": "apple",
        "netfl1x": "netflix",
        "netfllx": "netflix",
    }

    # Suspicious keywords commonly found in phishing URLs
    SUSPICIOUS_KEYWORDS: set = {
        "login", "account", "verify", "secure", "update",
        "confirm", "signin", "banking", "password", "credential",
        "suspend", "alert", "notification", "unlock",
    }

    # Well-known legitimate domains (not exhaustive, but covers common ones)
    KNOWN_SAFE_DOMAINS: set = {
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "github.com", "stackoverflow.com", "wikipedia.org",
        "youtube.com", "twitter.com", "linkedin.com", "netflix.com",
        "paypal.com", "reddit.com",
    }

    def __init__(self) -> None:
        """Initialize the threat analyzer with logging."""
        self._logger = setup_logger(__name__)

    def analyze_url(self, url: str) -> ThreatReport:
        """Analyze a URL for potential threats using heuristic checks.

        Runs all URL-based heuristic checks and produces a threat report
        with risk scoring.

        Args:
            url: The URL to analyze.

        Returns:
            ThreatReport with risk assessment and indicators.
        """
        self._logger.info(f"Analyzing URL: {url}")

        indicators: List[ThreatIndicator] = []

        # Run all URL-based checks
        url_checks = [
            self._check_ip_based_url,
            self._check_suspicious_tld,
            self._check_excessive_subdomains,
            self._check_url_length,
            self._check_suspicious_keywords,
            self._check_typosquatting,
        ]

        for check in url_checks:
            result = check(url)
            if result is not None:
                indicators.append(result)

        # Calculate risk score and level
        risk_score = self._calculate_risk_score(indicators)
        risk_level = self._determine_risk_level(risk_score)

        # Generate summary
        if indicators:
            summary = (
                f"Found {len(indicators)} threat indicator(s). "
                f"Risk level: {risk_level} (score: {risk_score}/100)."
            )
        else:
            summary = "No threats detected. URL appears safe."

        report = ThreatReport(
            url=url,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            summary=summary,
            analyzed_at=datetime.utcnow(),
        )

        self._logger.info(
            f"URL analysis complete: {risk_level} "
            f"(score={risk_score}, indicators={len(indicators)})"
        )

        return report

    def analyze_html(self, html_content: str, url: str) -> ThreatReport:
        """Analyze HTML content and URL together for threats.

        Runs both URL-based and HTML-based heuristic checks for a
        comprehensive threat assessment.

        Args:
            html_content: The HTML source of the page.
            url: The URL the HTML was fetched from.

        Returns:
            ThreatReport with combined risk assessment.
        """
        self._logger.info(f"Analyzing HTML content for: {url}")

        indicators: List[ThreatIndicator] = []

        # Run URL-based checks
        url_checks = [
            self._check_ip_based_url,
            self._check_suspicious_tld,
            self._check_excessive_subdomains,
            self._check_url_length,
            self._check_suspicious_keywords,
            self._check_typosquatting,
        ]

        for check in url_checks:
            result = check(url)
            if result is not None:
                indicators.append(result)

        # Run HTML-based checks
        html_checks = [
            self._check_hidden_iframes,
            self._check_suspicious_forms,
            self._check_obfuscated_js,
            self._check_external_resources,
            self._check_data_uri_abuse,
            self._check_meta_refresh_redirect,
        ]

        for check in html_checks:
            result = check(html_content)
            if result is not None:
                indicators.append(result)

        # Calculate risk score and level
        risk_score = self._calculate_risk_score(indicators)
        risk_level = self._determine_risk_level(risk_score)

        # Generate summary
        if indicators:
            summary = (
                f"Found {len(indicators)} threat indicator(s) in URL and content. "
                f"Risk level: {risk_level} (score: {risk_score}/100)."
            )
        else:
            summary = "No threats detected in URL or page content."

        report = ThreatReport(
            url=url,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            summary=summary,
            analyzed_at=datetime.utcnow(),
        )

        self._logger.info(
            f"HTML analysis complete: {risk_level} "
            f"(score={risk_score}, indicators={len(indicators)})"
        )

        return report

    # -------------------------------------------------------------------------
    # URL-based heuristic checks
    # -------------------------------------------------------------------------

    def _check_ip_based_url(self, url: str) -> Optional[ThreatIndicator]:
        """Check if the URL uses an IP address instead of a domain name.

        IP-based URLs are commonly used in phishing attacks to avoid
        domain-based blocklists. This is a critical severity indicator
        because legitimate services rarely expose user-facing URLs via
        raw IP addresses.

        Args:
            url: The URL to check.

        Returns:
            ThreatIndicator if an IP address is detected, None otherwise.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # IPv4 pattern
        ipv4_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}$"
        )
        # IPv6 pattern (simplified)
        ipv6_pattern = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")

        if ipv4_pattern.match(hostname) or ipv6_pattern.match(hostname):
            return ThreatIndicator(
                category="phishing",
                description="URL uses an IP address instead of a domain name",
                severity="critical",
                evidence=f"Host: {hostname}",
            )
        return None

    def _check_suspicious_tld(self, url: str) -> Optional[ThreatIndicator]:
        """Check if the URL uses a TLD commonly associated with phishing.

        Certain TLDs offer free or very cheap domain registration and
        are disproportionately used for malicious purposes.

        Args:
            url: The URL to check.

        Returns:
            ThreatIndicator if a suspicious TLD is found, None otherwise.
        """
        extracted = tldextract.extract(url)
        tld = extracted.suffix.lower()

        # Handle multi-part suffixes (e.g., co.uk) by checking the last part
        tld_parts = tld.split(".")
        primary_tld = tld_parts[-1] if tld_parts else tld

        if primary_tld in self.SUSPICIOUS_TLDS:
            return ThreatIndicator(
                category="phishing",
                description=f"URL uses suspicious TLD '.{primary_tld}' commonly associated with phishing",
                severity="medium",
                evidence=f"TLD: .{primary_tld}",
            )
        return None

    def _check_excessive_subdomains(self, url: str) -> Optional[ThreatIndicator]:
        """Check if the URL has an excessive number of subdomains.

        Phishing URLs often use many subdomains to make the URL appear
        to belong to a legitimate service (e.g., secure.login.bank.evil.com).

        Args:
            url: The URL to check.

        Returns:
            ThreatIndicator if more than 3 subdomains are found, None otherwise.
        """
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain

        if subdomain:
            parts = subdomain.split(".")
            # Filter out empty parts
            parts = [p for p in parts if p]
            if len(parts) > 3:
                return ThreatIndicator(
                    category="phishing",
                    description="URL has an excessive number of subdomains",
                    severity="medium",
                    evidence=f"Subdomains: {subdomain} ({len(parts)} levels)",
                )
        return None

    def _check_url_length(self, url: str) -> Optional[ThreatIndicator]:
        """Check if the URL is excessively long.

        Extremely long URLs are sometimes used to hide malicious
        content or confuse users about the true destination.

        Args:
            url: The URL to check.

        Returns:
            ThreatIndicator if URL exceeds 100 characters, None otherwise.
        """
        if len(url) > 100:
            return ThreatIndicator(
                category="suspicious",
                description="URL is excessively long, which may indicate obfuscation",
                severity="low",
                evidence=f"URL length: {len(url)} characters",
            )
        return None

    def _check_suspicious_keywords(self, url: str) -> Optional[ThreatIndicator]:
        """Check for phishing-related keywords in the URL path.

        Keywords like 'login', 'verify', 'account' in the path of a URL
        that is not a well-known legitimate domain suggest phishing.

        Args:
            url: The URL to check.

        Returns:
            ThreatIndicator if suspicious keywords are found on a
            non-trusted domain, None otherwise.
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        hostname = parsed.hostname or ""

        # Check if this is a known safe domain
        extracted = tldextract.extract(url)
        registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()

        if registered_domain in self.KNOWN_SAFE_DOMAINS:
            return None

        # Check for suspicious keywords in the path
        found_keywords = []
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in path:
                found_keywords.append(keyword)

        if found_keywords:
            return ThreatIndicator(
                category="phishing",
                description="URL path contains suspicious keywords commonly used in phishing",
                severity="high",
                evidence=f"Keywords found: {', '.join(found_keywords)} in path '{parsed.path}'",
            )
        return None

    def _check_typosquatting(self, url: str) -> Optional[ThreatIndicator]:
        """Check if the domain appears to be typosquatting a known brand.

        Typosquatting uses domain names that are slight misspellings of
        well-known brands to trick users.

        Args:
            url: The URL to check.

        Returns:
            ThreatIndicator if typosquatting is detected, None otherwise.
        """
        extracted = tldextract.extract(url)
        domain = extracted.domain.lower()

        for typo, brand in self.TYPOSQUAT_PATTERNS.items():
            if typo in domain and domain != brand:
                return ThreatIndicator(
                    category="phishing",
                    description=f"Domain appears to be typosquatting '{brand}'",
                    severity="high",
                    evidence=f"Domain '{domain}' contains typosquat pattern '{typo}'",
                )
        return None

    # -------------------------------------------------------------------------
    # HTML-based heuristic checks
    # -------------------------------------------------------------------------

    def _check_hidden_iframes(self, html: str) -> Optional[ThreatIndicator]:
        """Check for hidden iframes in the HTML content.

        Hidden iframes are commonly used to load malicious content
        invisibly, such as credential harvesting forms or exploit kits.

        Args:
            html: The HTML content to analyze.

        Returns:
            ThreatIndicator if hidden iframes are found, None otherwise.
        """
        soup = BeautifulSoup(html, "html.parser")
        iframes = soup.find_all("iframe")

        for iframe in iframes:
            style = (iframe.get("style") or "").lower()
            width = iframe.get("width", "")
            height = iframe.get("height", "")

            is_hidden = (
                "display:none" in style.replace(" ", "")
                or "display: none" in style
                or "visibility:hidden" in style.replace(" ", "")
                or "visibility: hidden" in style
                or width == "0"
                or height == "0"
                or (width == "1" and height == "1")
            )

            if is_hidden:
                src = iframe.get("src", "unknown")
                return ThreatIndicator(
                    category="malware",
                    description="Page contains hidden iframe(s) that may load malicious content",
                    severity="high",
                    evidence=f"Hidden iframe src: {src}",
                )
        return None

    def _check_suspicious_forms(self, html: str) -> Optional[ThreatIndicator]:
        """Check for forms that submit data to external domains.

        Forms with action URLs pointing to different domains may be
        harvesting credentials and sending them to attacker-controlled servers.

        Args:
            html: The HTML content to analyze.

        Returns:
            ThreatIndicator if suspicious forms are found, None otherwise.
        """
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action", "")
            if action and action.startswith(("http://", "https://")):
                return ThreatIndicator(
                    category="phishing",
                    description="Form submits data to an external URL",
                    severity="medium",
                    evidence=f"Form action: {action}",
                )
        return None

    def _check_obfuscated_js(self, html: str) -> Optional[ThreatIndicator]:
        """Check for obfuscated JavaScript patterns.

        Functions like eval(), document.write(), and unescape() are
        commonly used to hide malicious JavaScript code.

        Args:
            html: The HTML content to analyze.

        Returns:
            ThreatIndicator if obfuscation patterns are found, None otherwise.
        """
        # Patterns indicating JavaScript obfuscation
        obfuscation_patterns = [
            (r"\beval\s*\(", "eval()"),
            (r"\bdocument\.write\s*\(", "document.write()"),
            (r"\bunescape\s*\(", "unescape()"),
            (r"String\.fromCharCode", "String.fromCharCode"),
            (r"\\x[0-9a-fA-F]{2}", "hex-encoded strings"),
        ]

        found_patterns = []
        for pattern, name in obfuscation_patterns:
            if re.search(pattern, html):
                found_patterns.append(name)

        if found_patterns:
            return ThreatIndicator(
                category="malware",
                description="Page contains potentially obfuscated JavaScript",
                severity="medium",
                evidence=f"Patterns found: {', '.join(found_patterns)}",
            )
        return None

    def _check_external_resources(self, html: str) -> Optional[ThreatIndicator]:
        """Check for excessive loading of external resources.

        Pages that load an unusually high number of external scripts or
        resources may be involved in cryptomining, ad fraud, or data exfiltration.

        Args:
            html: The HTML content to analyze.

        Returns:
            ThreatIndicator if more than 20 external resources are found,
            None otherwise.
        """
        soup = BeautifulSoup(html, "html.parser")

        external_count = 0

        # Count external scripts
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src.startswith(("http://", "https://", "//")):
                external_count += 1

        # Count external stylesheets
        for link in soup.find_all("link", rel="stylesheet"):
            href = link.get("href", "")
            if href.startswith(("http://", "https://", "//")):
                external_count += 1

        if external_count > 20:
            return ThreatIndicator(
                category="suspicious",
                description="Page loads an excessive number of external resources",
                severity="low",
                evidence=f"External resources: {external_count}",
            )
        return None

    def _check_data_uri_abuse(self, html: str) -> Optional[ThreatIndicator]:
        """Check for suspicious use of data URIs.

        Data URIs in scripts or links can be used to embed malicious
        content directly in the page without making network requests.

        Args:
            html: The HTML content to analyze.

        Returns:
            ThreatIndicator if data URI abuse is detected, None otherwise.
        """
        # Check for data URIs in script src or link href
        data_uri_pattern = re.compile(
            r'(?:src|href)\s*=\s*["\']data:', re.IGNORECASE
        )

        matches = data_uri_pattern.findall(html)
        if matches:
            return ThreatIndicator(
                category="malware",
                description="Page uses data URIs in scripts or links, which may hide malicious content",
                severity="medium",
                evidence=f"Data URI references found: {len(matches)}",
            )
        return None

    def _check_meta_refresh_redirect(self, html: str) -> Optional[ThreatIndicator]:
        """Check for meta refresh redirects to different domains.

        Meta refresh tags that redirect to a different domain can be
        used to bypass security filters and redirect users to phishing pages.

        Args:
            html: The HTML content to analyze.

        Returns:
            ThreatIndicator if meta refresh redirect is found, None otherwise.
        """
        soup = BeautifulSoup(html, "html.parser")
        meta_tags = soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})

        for meta in meta_tags:
            content = meta.get("content", "")
            # Extract URL from content like "0;url=http://evil.com"
            url_match = re.search(r"url\s*=\s*(.+)", content, re.IGNORECASE)
            if url_match:
                redirect_url = url_match.group(1).strip().strip("'\"")
                if redirect_url.startswith(("http://", "https://")):
                    return ThreatIndicator(
                        category="phishing",
                        description="Page uses meta refresh to redirect to an external URL",
                        severity="high",
                        evidence=f"Redirect target: {redirect_url}",
                    )
        return None

    # -------------------------------------------------------------------------
    # Risk scoring
    # -------------------------------------------------------------------------

    def _calculate_risk_score(self, indicators: List[ThreatIndicator]) -> int:
        """Calculate an overall risk score from threat indicators.

        Uses weighted severity scoring: critical=35, high=20, medium=10, low=5.
        The score is capped at 100.

        Args:
            indicators: List of threat indicators found during analysis.

        Returns:
            Integer risk score from 0 to 100.
        """
        severity_weights = {
            "critical": 35,
            "high": 20,
            "medium": 10,
            "low": 5,
        }

        total = 0
        for indicator in indicators:
            weight = severity_weights.get(indicator.severity.lower(), 5)
            total += weight

        return min(total, 100)

    def _determine_risk_level(self, score: int) -> str:
        """Determine the human-readable risk level from a score.

        Thresholds:
            0-20: safe
            21-40: low
            41-60: medium
            61-80: high
            81-100: critical

        Args:
            score: Risk score from 0 to 100.

        Returns:
            Risk level string (safe, low, medium, high, critical).
        """
        if score <= 20:
            return "safe"
        elif score <= 40:
            return "low"
        elif score <= 60:
            return "medium"
        elif score <= 80:
            return "high"
        else:
            return "critical"
