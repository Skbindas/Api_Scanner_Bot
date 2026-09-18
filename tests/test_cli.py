from api_scanner.cli import build_parser


def test_cli_help_parser() -> None:
    parser = build_parser()
    args = parser.parse_args(["analyze-url", "https://example.com"])
    assert args.command == "analyze-url"
    assert args.url == "https://example.com"


def test_scan_cli_options() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "scan",
            "https://example.com",
            "--export",
            "json",
            "html",
            "--timeout",
            "45",
            "--headed",
        ]
    )
    assert args.export == ["json", "html"]
    assert args.timeout == 45
    assert args.headed is True
