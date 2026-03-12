import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[36m",      # cyan
        logging.INFO: "\033[32m",       # green
        logging.WARNING: "\033[33m",    # yellow
        logging.ERROR: "\033[31m",      # red
        logging.CRITICAL: "\033[1;31m", # bold red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class PlainFormatter(logging.Formatter):
    pass


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        import json
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


_FORMATTERS = {
    "color": ColorFormatter,
    "plain": PlainFormatter,
    "json": JSONFormatter,
}

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    app_name: str = "intrusion_inspector",
    *,
    verbose: bool = False,
    log_dir: str | Path | None = None,
    log_format: str | None = None,
) -> logging.Logger:
    root_logger = logging.getLogger(app_name)
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    root_logger.handlers.clear()

    fmt_name = log_format or os.getenv("LOG_FORMAT", "color")
    level_name = os.getenv("LOG_LEVEL", "DEBUG" if verbose else "INFO")
    root_logger.setLevel(getattr(logging, level_name.upper(), logging.INFO))

    formatter_cls = _FORMATTERS.get(fmt_name, ColorFormatter)
    formatter = formatter_cls(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    root_logger.addHandler(console)

    if log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        file_formatter = PlainFormatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)
        file_handler = RotatingFileHandler(
            log_path / f"{app_name}.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"intrusion_inspector.{name}")
