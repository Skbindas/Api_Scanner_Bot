"""
Logging configuration for the API Scanner Bot.

Provides a setup function that creates loggers with both file and console
handlers, using rotating file handlers to manage log file size.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


def setup_logger(
    name: str, level: str = "INFO", log_dir: Optional[str] = None
) -> logging.Logger:
    """Create and configure a logger with file and console handlers.

    Creates a logger that writes to both a rotating log file and the console.
    The log directory is created automatically if it does not exist.

    Args:
        name: Name for the logger (typically __name__ of the calling module).
        level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_dir: Optional path to the log directory. Defaults to "logs" if
                 not specified.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid adding duplicate handlers if logger already configured
    if logger.handlers:
        return logger

    # Log format
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Create logs directory if it doesn't exist
    log_path = Path(log_dir) if log_dir else Path("logs")
    log_path.mkdir(parents=True, exist_ok=True)

    # Rotating file handler: 5MB max, 3 backup files
    file_handler = RotatingFileHandler(
        filename=log_path / "scanner.log",
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    file_handler.setFormatter(formatter)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
