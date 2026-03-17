"""Colored logging with optional timestamps (impacket -ts style)."""

import logging
import sys
from datetime import datetime, timezone

SUCCESS = 25  # custom level between INFO and WARNING
logging.addLevelName(SUCCESS, "SUCCESS")

_COLORS = {
    "green": "\033[1;92m",
    "blue": "\033[1;94m",
    "yellow": "\033[1;93m",
    "red": "\033[1;91m",
    "cyan": "\033[1;96m",
    "reset": "\033[0m",
}

_BULLETS = {
    logging.DEBUG: ("[*]", "cyan"),
    logging.INFO: ("[*]", "blue"),
    logging.WARNING: ("[!]", "yellow"),
    logging.ERROR: ("[-]", "red"),
    logging.CRITICAL: ("[-]", "red"),
    SUCCESS: ("[+]", "green"),
}


class ColorFormatter(logging.Formatter):
    """Colored output formatter matching impacket style."""

    def __init__(self, timestamps: bool = False) -> None:
        super().__init__()
        self.timestamps = timestamps

    def format(self, record: logging.LogRecord) -> str:
        bullet, color_name = _BULLETS.get(
            record.levelno,
            ("[*]", "blue"),
        )
        color = _COLORS.get(color_name, "")
        reset = _COLORS["reset"]
        msg = record.getMessage()

        if self.timestamps:
            ts = (
                datetime.now(tz=timezone.utc)
                .astimezone()
                .strftime(
                    "%Y-%m-%d %H:%M:%S",
                )
            )
            return f"[{ts}] {color}{bullet}{reset} {msg}"
        return f"{color}{bullet}{reset} {msg}"


def setup_logger(
    timestamps: bool = False,
    debug: bool = False,
) -> logging.Logger:
    """Configure and return the bigpotam logger."""
    logger = logging.getLogger("bigpotam")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter(timestamps=timestamps))
    logger.addHandler(handler)

    return logger


def success(logger: logging.Logger, msg: str, *args, **kwargs) -> None:
    """Log a success message with [+] prefix."""
    logger.log(SUCCESS, msg, *args, **kwargs)
