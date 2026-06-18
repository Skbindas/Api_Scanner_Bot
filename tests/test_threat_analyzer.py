"""
Tests for the ThreatAnalyzer heuristic-based detection module.
"""

import pytest

from api_scanner.security.threat_analyzer import ThreatAnalyzer


@pytest.fixture
def analyzer():
    """Create a ThreatAnalyzer instance for testing."""
    return ThreatAnalyzer()


class TestUrlAnalysis:
    """Tests for URL-based threat analysis."""

    def test_safe_url_google(self, analyzer):
        """Known safe URL google.com gets a low risk score."""
        report = analyzer.analyze_url("https://www.google.com")
        assert report.risk_score < 30

    def test_safe_url_github(self, analyzer):
        """Known safe URL github.com gets a low risk score."""
        report = analyzer.analyze_url("https://github.com")
        assert report.risk_score < 30

    def test_ip_based_url(self, analyzer):
        """IP-based URL with login path gets a high risk score."""
        report = analyzer.analyze_url("http://192.168.1.1/login")
        assert report.risk_score > 40

    def test_suspicious_tld(self, analyzer):
        """URL with suspicious TLD (.tk) gets flagged."""
        report = analyzer.analyze_url("http://free-prizes.tk/win")
        assert report.risk_score > 0
        # Verify that TLD indicator was found
        tld_indicators = [i for i in report.indicators if ".tk" in i.evidence]
        assert len(tld_indicators) > 0

    def test_excessive_subdomains(self, analyzer):
        """URL with excessive subdomains gets a non-zero score."""
        report = analyzer.analyze_url("http://a.b.c.d.e.example.com")
        assert report.risk_score > 0

    def test_typosquatting(self, analyzer):
        """URL with typosquatting pattern gets a high risk score."""
        report = analyzer.analyze_url("http://paypa1.com/login")
        assert report.risk_score > 30


class TestHtmlAnalysis:
    """Tests for HTML content-based threat analysis."""

    def test_html_hidden_iframe(self, analyzer):
        """HTML with hidden iframe is detected."""
        html = '<html><body><iframe src="http://evil.com" style="display:none"></iframe></body></html>'
        report = analyzer.analyze_html(html, "http://example.com")
        categories = [i.category for i in report.indicators]
        assert "malware" in categories

    def test_html_obfuscated_js(self, analyzer):
        """HTML with eval() is detected as obfuscated JavaScript."""
        html = '<html><body><script>eval("alert(1)")</script></body></html>'
        report = analyzer.analyze_html(html, "http://example.com")
        categories = [i.category for i in report.indicators]
        assert "malware" in categories

    def test_html_suspicious_form(self, analyzer):
        """HTML with external form action is detected."""
        html = '<html><body><form action="http://evil.com/steal"></form></body></html>'
        report = analyzer.analyze_html(html, "http://example.com")
        categories = [i.category for i in report.indicators]
        assert "phishing" in categories


class TestRiskLevels:
    """Tests for risk score to risk level mapping."""

    def test_risk_level_safe(self, analyzer):
        """Score 0-20 maps to 'safe'."""
        assert analyzer._determine_risk_level(0) == "safe"
        assert analyzer._determine_risk_level(10) == "safe"
        assert analyzer._determine_risk_level(20) == "safe"

    def test_risk_level_critical(self, analyzer):
        """Score 81-100 maps to 'critical'."""
        assert analyzer._determine_risk_level(81) == "critical"
        assert analyzer._determine_risk_level(90) == "critical"
        assert analyzer._determine_risk_level(100) == "critical"
