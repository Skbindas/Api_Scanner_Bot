# Contributing to API Scanner Pro

Thank you for considering a contribution.

## Development setup

1. Install Python 3.11+.
2. Clone the repository and create a virtual environment.
3. Install dependencies with `pip install -r requirements.txt`.
4. Install the Playwright browser with `playwright install chromium`.
5. Run the test suite with `pytest -q`.

## Before opening an issue

Search existing issues first. For security vulnerabilities, do **not** open a public issue; follow [SECURITY.md](SECURITY.md).

## Pull requests

1. Fork the repository.
2. Create a focused branch from `main`.
3. Add or update tests for behavioral changes.
4. Keep changes scoped and document user-visible behavior.
5. Run `pytest -q` locally.
6. Run `python -m api_scanner.cli --help` to verify the CLI entry point.
7. Open a pull request using the repository template.

All pull requests are checked by GitHub Actions. Maintainers may request changes before merging.

## Contribution principles

- Prefer small, reviewable changes.
- Do not commit secrets, API keys, session tokens, scan output, or personal data.
- Security-sensitive behavior should include tests and documentation.
- Explain heuristic limitations rather than presenting scanner results as guaranteed verdicts.

## Code of conduct

Be respectful, technical, and constructive. Contributions that violate the project's security or collaboration standards may be rejected.
