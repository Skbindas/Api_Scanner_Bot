# API Scanner Pro v2.0

![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)
![License MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Version 2.0](https://img.shields.io/badge/Version-2.0.0-orange.svg)

## Overview

**API Scanner Pro** is a professional desktop application for scanning websites, detecting API endpoints, analyzing security threats, and exporting comprehensive reports. Built with Python, it combines network interception via Playwright with heuristic-based threat analysis and a modern Tkinter GUI.

---

### Overview (Hindi)

**API Scanner Pro** एक professional desktop application है जो websites को scan करता है, API endpoints detect करता है, security threats analyze करता है, और comprehensive reports export करता है। Python में built, यह Playwright के माध्यम से network interception को heuristic-based threat analysis और modern Tkinter GUI के साथ combine करता है।

---

## Features

### Scanning
- Full browser-based network interception using Playwright
- Automatic API endpoint detection from captured traffic
- Cookie, localStorage, and sessionStorage extraction
- HTML metadata and Open Graph tag parsing
- Configurable scan timeouts and retries

### Security Analysis
- Heuristic-based URL threat detection (phishing, typosquatting, suspicious TLDs)
- HTML content analysis (hidden iframes, obfuscated JS, suspicious forms)
- Shodan integration for host intelligence (open ports, CVEs, services)
- Risk scoring with severity levels: safe, low, medium, high, critical

### Export
- JSON export with full metadata and scanner version info
- CSV export with separate files for requests, endpoints, and responses
- HTML report with professional styling, card-based layout, and responsive design
- Batch export via ExportManager for all formats at once

### User Interface
- Modern Tkinter-based GUI with tabbed interface
- Async scanning with real-time progress feedback
- Dedicated tabs: Scanner, Security, Results, Reports
- Custom widgets: StatusBar, URLInput, LogConsole, RiskBadge

---

## Architecture

```
Api_Scanner_Bot/
├── api_scanner/                  # Main package
│   ├── __init__.py               # Package init, version = "2.0.0"
│   ├── config.py                 # AppConfig dataclass (env-based settings)
│   ├── exceptions.py             # Custom exception hierarchy
│   ├── logger.py                 # Logging setup (file + console)
│   ├── utils.py                  # URL validation, rate limiter, retry, serialization
│   ├── main.py                   # Application entry point
│   ├── scanner/                  # Core scanning engine
│   │   ├── models.py             # RequestData, ResponseData, ScanResult, etc.
│   │   ├── network_scanner.py    # Playwright-based network interception
│   │   ├── storage_analyzer.py   # Cookie/storage extraction
│   │   └── meta_analyzer.py      # HTML metadata parsing
│   ├── security/                 # Security analysis module
│   │   ├── models.py             # ThreatReport, SecurityFinding, etc.
│   │   ├── threat_analyzer.py    # Heuristic URL/HTML threat detection
│   │   └── shodan_scanner.py     # Shodan API integration
│   ├── exporters/                # Report export system
│   │   ├── base.py               # BaseExporter abstract class
│   │   ├── json_exporter.py      # JSON report generation
│   │   ├── csv_exporter.py       # CSV report generation (pandas)
│   │   ├── html_exporter.py      # Standalone HTML report generation
│   │   └── export_manager.py     # Multi-format export coordinator
│   └── ui/                       # Tkinter GUI
│       ├── app.py                # Main ScannerApp window
│       ├── async_handler.py      # Daemon thread + event loop for async ops
│       ├── widgets.py            # Custom reusable widgets
│       ├── scanner_tab.py        # URL scan tab
│       ├── security_tab.py       # Security analysis tab
│       ├── results_tab.py        # Results display tab
│       └── reports_tab.py        # Export/reports tab
├── tests/                        # Test suite
│   ├── conftest.py               # Shared fixtures
│   ├── test_config.py            # Config loading tests
│   ├── test_utils.py             # Utility function tests
│   ├── test_models.py            # Data model tests
│   ├── test_threat_analyzer.py   # Threat detection tests
│   └── test_exporters.py         # Export system tests
├── logs/                         # Application logs
├── .env                          # Environment configuration (gitignored)
├── .env.example                  # Example configuration template
├── requirements.txt              # Python dependencies
├── pyproject.toml                # Project metadata
└── README.md                     # This file
```

---

## Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager

### Step-by-Step Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-username/Api_Scanner_Bot.git
cd Api_Scanner_Bot

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Playwright browser (required for scanning)
playwright install chromium

# 5. Configure environment
cp .env.example .env
# Edit .env with your settings (e.g., add your Shodan API key)

# 6. Launch the application
python3 -m api_scanner.main
```

---

## Configuration

All configuration is managed through environment variables. Create a `.env` file (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `SHODAN_API_KEY` | `""` | Shodan API key for host security scanning |
| `SCAN_TIMEOUT` | `30` | Maximum seconds to wait for a page scan |
| `MAX_RETRIES` | `3` | Number of retries for failed network requests |
| `RATE_LIMIT_DELAY` | `1.0` | Minimum seconds between rate-limited requests |
| `OUTPUT_DIR` | `scan_results` | Directory for storing exported reports |
| `HEADLESS` | `true` | Run browser in headless mode (no visible window) |
| `LOG_LEVEL` | `INFO` | Logging verbosity: DEBUG, INFO, WARNING, ERROR, CRITICAL |

---

## Usage

### Launch the GUI

```bash
python3 -m api_scanner.main
```

### Scan Workflow

1. Enter a target URL in the Scanner tab
2. Click "Scan" to start the browser-based analysis
3. View captured API endpoints and network requests in the Results tab
4. Check Security tab for threat analysis results
5. Export reports in JSON, CSV, or HTML format via the Reports tab

### Export Formats

- **JSON**: Complete structured data with metadata, ideal for programmatic access
- **CSV**: Tabular data split into requests.csv, api_endpoints.csv, and responses.csv
- **HTML**: Self-contained professional report with embedded CSS, suitable for sharing

---

## Development

### Setup

```bash
# Clone and install in development mode
git clone https://github.com/your-username/Api_Scanner_Bot.git
cd Api_Scanner_Bot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

### Running Tests

```bash
# Run full test suite
python3 -m pytest tests/ -v

# Run specific test module
python3 -m pytest tests/test_threat_analyzer.py -v

# Run with coverage (if pytest-cov installed)
python3 -m pytest tests/ --cov=api_scanner -v
```

### Code Quality

```bash
# Check all files compile without errors
python3 -m py_compile api_scanner/__init__.py
python3 -m py_compile api_scanner/main.py

# Verify imports work
python3 -c "import api_scanner; print(api_scanner.__version__)"
```

---

## Testing (Hindi)

```bash
# पूरा test suite चलाएं
python3 -m pytest tests/ -v

# Specific module test करें
python3 -m pytest tests/test_threat_analyzer.py -v
```

---

## License

This project is licensed under the MIT License.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`python3 -m pytest tests/ -v`)
5. Commit your changes with descriptive messages
6. Push and open a Pull Request
