"""
Entry point for the API Scanner Bot application.

Creates the application configuration, sets up logging, ensures
required directories exist, and launches the GUI.
"""

from api_scanner.config import AppConfig
from api_scanner.logger import setup_logger
from api_scanner.ui.app import ScannerApp
from api_scanner.utils import ensure_directories


def main() -> None:
    """Initialize and run the API Scanner Pro application.

    Sets up configuration, logging, output directories, and launches
    the Tkinter GUI main loop.
    """
    # Initialize configuration
    config = AppConfig()

    # Set up logging
    logger = setup_logger("api_scanner", config.log_level)
    logger.info("Starting API Scanner Pro v2.0")

    # Ensure output directories exist
    ensure_directories(config.output_dir)

    # Create and run the application
    app = ScannerApp(config)
    app.mainloop()

    logger.info("API Scanner Pro shutting down")


if __name__ == "__main__":
    main()
