"""Command-line interface for API Scanner Pro.

The CLI exposes the deterministic URL analyzer and browser-based scanner
without requiring the Tkinter GUI.
"""

import argparse
import asyncio
import json
from typing import Sequence

from api_scanner.config import AppConfig
from api_scanner.scanner.network_scanner import NetworkScanner
from api_scanner.security.threat_analyzer import ThreatAnalyzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="api-scanner",
        description="Scan websites for API endpoints and security indicators.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    url_parser = subparsers.add_parser(
        "analyze-url", help="Run deterministic URL threat heuristics."
    )
    url_parser.add_argument("url", help="URL to analyze.")
    url_parser.add_argument(
        "--json", action="store_true", help="Print machine-readable JSON."
    )

    scan_parser = subparsers.add_parser(
        "scan", help="Run a browser-based network/API scan."
    )
    scan_parser.add_argument("url", help="Authorized target URL to scan.")
    scan_parser.add_argument(
        "--export",
        nargs="+",
        choices=("json", "csv", "html"),
        default=(),
        help="Export formats to write after scanning.",
    )
    scan_parser.add_argument(
        "--output-dir",
        default="scan_results",
        help="Directory for exported reports.",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Navigation timeout in seconds.",
    )
    scan_parser.add_argument(
        "--headed",
        action="store_true",
        help="Run Chromium with a visible window.",
    )
    return parser


def _threat_report_dict(report) -> dict:
    return {
        "url": report.url,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "summary": report.summary,
        "indicators": [
            {
                "category": i.category,
                "description": i.description,
                "severity": i.severity,
                "evidence": i.evidence,
            }
            for i in report.indicators
        ],
        "analyzed_at": report.analyzed_at.isoformat(),
    }


async def _run_scan(args: argparse.Namespace) -> int:
    config = AppConfig(
        scan_timeout=args.timeout,
        output_dir=args.output_dir,
        headless=not args.headed,
    )
    scanner = NetworkScanner(config)
    result = await scanner.scan(args.url)

    print(f"Target: {result.url}")
    print(f"Requests: {len(result.requests)}")
    print(f"Responses: {len(result.responses)}")
    print(f"API endpoints: {len(result.api_endpoints)}")
    print(f"Duration: {result.scan_duration:.2f}s")

    if result.errors:
        print(f"Non-fatal errors: {len(result.errors)}")

    if args.export:
        from api_scanner.exporters.export_manager import ExportManager

        paths = ExportManager(config).export_all(result, list(args.export))
        for fmt, path in paths.items():
            print(f"{fmt.upper()}: {path}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze-url":
        report = ThreatAnalyzer().analyze_url(args.url)
        if args.json:
            print(json.dumps(_threat_report_dict(report), indent=2))
        else:
            print(report.summary)
            for indicator in report.indicators:
                print(
                    f"- [{indicator.severity.upper()}] "
                    f"{indicator.category}: {indicator.description}"
                )
        return 0

    if args.command == "scan":
        return asyncio.run(_run_scan(args))

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
