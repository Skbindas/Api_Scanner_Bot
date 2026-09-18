# API Scanner Pro v2.0

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)
![License MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Version 2.0](https://img.shields.io/badge/Version-2.0.0-orange.svg)

**API Scanner Pro** is an open-source Python security and developer utility for browser-based API discovery, network inspection, heuristic threat analysis, and report generation.

> **Status:** Active development. The scanner produces evidence and heuristic indicators for investigation; it does not provide definitive vulnerability or malware verdicts.

## Features

- Browser network interception with Playwright.
- Likely API endpoint detection from URL and response-content heuristics.
- Cookie, localStorage, and sessionStorage inspection.
- HTML metadata and security-header analysis.
- Deterministic URL/HTML threat heuristics, including IP hosts, suspicious TLDs, typosquatting patterns, suspicious forms, hidden iframes, and obfuscated JavaScript.
- Optional Shodan host intelligence.
- JSON, CSV, and standalone HTML report export.
- Tkinter desktop UI plus a scriptable CLI.
- Automated tests and GitHub Actions CI.

## Architecture

```text
Api_Scanner_Bot/
├── api_scanner/
│   ├── cli.py                   # Scriptable command-line interface
│   ├── main.py                  # Tkinter application entry point
│   ├── config.py                # Environment-based configuration
│   ├── exceptions.py
│   ├── logger.py
│   ├── utils.py
│   ├── scanner/                 # Network capture, storage, metadata, models
│   ├── security/                # Threat analysis and optional Shodan integration
│   ├── exporters/               # JSON, CSV, HTML reporting
│   └── ui/                      # Tkinter interface
├── tests/
├── docs/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── pull_request_template.md
│   └── workflows/ci.yml
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── .env.example
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Installation

Requirements: Python 3.11+ and Chromium installed by Playwright for browser scans.

```bash
git clone https://github.com/Skbindas/Api_Scanner_Bot.git
cd Api_Scanner_Bot
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
playwright install chromium
```

Optional configuration is documented in `.env.example`.

## CLI

The CLI supports reproducible local analysis and automation without launching the Tkinter UI.

```bash
api-scanner --help
api-scanner analyze-url https://example.com
api-scanner analyze-url https://example.com --json
api-scanner scan https://example.com
api-scanner scan https://example.com --export json csv html
```

For a visible browser, custom timeout, or output directory:

```bash
api-scanner scan https://example.com --output-dir ./artifacts --timeout 45 --headed
```

The CLI reuses the project's scanning and export components.

## Reproducible usage evidence

This project documents **reproducible local usage instead of making unverifiable claims about external users or production traffic**.

See [docs/usage-example.md](docs/usage-example.md) for an end-to-end workflow. The test suite covers configuration, models, utilities, threat analysis, exporters, and CLI argument parsing.

Run the local checks:

```bash
pytest -q
python -m compileall -q api_scanner
python -m api_scanner.cli --help
```

GitHub Actions runs the tests and CLI/package smoke checks on Python 3.11, 3.12, and 3.13.

For the current adoption/implementation evidence snapshot, see [docs/oss-evidence.md](docs/oss-evidence.md).

## Release process

Versioned releases are built from semantic Git tags. The repository contains an automated tagged-release workflow that builds the Python distribution and validates it with `twine check`.

The v2.0.0 release should be created only after the `v2.0.0` tag is created on the validated `main` commit. See [docs/release.md](docs/release.md) for the maintainer checklist.

## GUI workflow

1. Enter an authorized target URL.
2. Start the browser-based scan.
3. Review captured requests and likely API endpoints.
4. Review security indicators and metadata.
5. Export JSON, CSV, or HTML reports.

## Security and privacy

The scanner can capture request/response metadata and browser storage from a target. Treat scan output as potentially sensitive.

- Only scan systems you own or have explicit permission to assess.
- Never commit API keys, session tokens, credentials, cookies, or private scan output.
- Review generated reports before sharing them.
- Read [SECURITY.md](SECURITY.md) for vulnerability reporting and safe-use guidance.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `SHODAN_API_KEY` | empty | Optional Shodan host intelligence |
| `SCAN_TIMEOUT` | `30` | Page navigation timeout in seconds |
| `MAX_RETRIES` | `3` | Retry count |
| `RATE_LIMIT_DELAY` | `1.0` | Minimum delay between rate-limited requests |
| `OUTPUT_DIR` | `scan_results` | Report output directory |
| `HEADLESS` | `true` | Browser visibility |
| `LOG_LEVEL` | `INFO` | Logging level |

## Development

```bash
pip install -e ".[dev]"
pytest -q
pytest -q tests/test_threat_analyzer.py
```

The threat-analysis tests are deterministic and do not require a live target.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request.

The repository includes structured bug/feature issue forms, a pull-request checklist, security guidance, and automated CI.

## License

API Scanner Pro is released under the [MIT License](LICENSE).

## Maintainer

Repository: https://github.com/Skbindas/Api_Scanner_Bot
