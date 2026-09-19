"""
Logging Subsystem for Alpha.

Provides structured file logging and optional stderr output, ensuring all logged
strings are sanitized and do not flood the console during interactive TUI execution.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional
from alpha.sanitizer import sanitize_string


_logger_initialized = False


def setup_logger(
    log_file: Optional[str] = None,
    log_level: str = "INFO",
    enable_console: bool = False
) -> logging.Logger:
    """Initialize root Alpha logger with file handler and optional console handler."""
    global _logger_initialized
    logger = logging.getLogger("alpha")
    
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)
    
    # Avoid duplicate handlers if setup_logger called multiple times
    if _logger_initialized:
        return logger
    
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_path,
                maxBytes=5 * 1024 * 1024,  # 5 MB
                backupCount=3,
                encoding="utf-8"
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(numeric_level)
            logger.addHandler(file_handler)
        except Exception:
            pass  # Fallback gracefully if filesystem permissions fail
            
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(numeric_level)
        logger.addHandler(console_handler)
        
    _logger_initialized = True
    return logger


def get_logger(name: str = "alpha") -> logging.Logger:
    """Get named logger under alpha hierarchy."""
    return logging.getLogger(f"alpha.{name}")


def log_safe(logger: logging.Logger, level: int, msg: str, *args) -> None:
    """Safely log a message after stripping potential ANSI/control sequences."""
    sanitized_msg = sanitize_string(msg, fallback="[empty log]")
    logger.log(level, sanitized_msg, *args)
