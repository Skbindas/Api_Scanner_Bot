# Reproducible usage example

This page documents a reproducible local workflow. The output below is intentionally a procedure rather than a claim about third-party usage.

## 1. Install

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows
# .venv\\Scripts\\activate

pip install -e ".[dev]"
playwright install chromium
```

## 2. Analyze a URL without browsing

Use the deterministic threat analyzer when you only need URL heuristics:

```bash
api-scanner analyze-url https://example.com
```

## 3. Run a browser scan

```bash
api-scanner scan https://example.com --export json html
```

The scan captures browser network activity, identifies likely API endpoints, analyzes browser storage and page metadata, and can export reports.

## 4. Run the test suite

```bash
pytest -q
```

The repository includes tests for configuration, models, utilities, threat analysis, and exporters. CI runs the suite on supported Python versions.

## Safety

Only scan targets you own or have explicit permission to assess. Heuristic findings are indicators for investigation, not definitive security verdicts.
