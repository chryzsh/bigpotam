import logging
import sys
from datetime import datetime


class ColorFormatter(logging.Formatter):
    """Colored output formatter matching impacket style."""

    COLORS = {
        "green": "\033[1;92m",
        "blue": "\033[1;94m",
        "yellow": "\033[1;93m",
        "red": "\033[1;91m",
        "cyan": "\033[1;96m",
        "reset": "\033[0m",
    }

    BULLETS = {
        logging.DEBUG: "[*]",
        logging.INFO: "[*]",
        logging.WARNING: "[!]",
        logging.ERROR: "[-]",
        logging.CRITICAL: "[-]",
    }

    BULLET_COLORS = {
        logging.DEBUG: "cyan",
        logging.INFO: "blue",
        logging.WARNING: "yellow",
        logging.ERROR: "red",
        logging.CRITICAL: "red",
    }

    SUCCESS = 25  # custom level between INFO and WARNING

    def __init__(self, timestamps=False):
        super().__init__()
        self.timestamps = timestamps
        logging.addLevelName(self.SUCCESS, "SUCCESS")

    def format(self, record):
        if record.levelno == self.SUCCESS:
            bullet = "[+]"
            color = self.COLORS["green"]
        else:
            bullet = self.BULLETS.get(record.levelno, "[*]")
            color = self.COLORS.get(
                self.BULLET_COLORS.get(record.levelno, "blue"), ""
            )

        reset = self.COLORS["reset"]
        msg = record.getMessage()

        if self.timestamps:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return f"[{ts}] {color}{bullet}{reset} {msg}"
        return f"{color}{bullet}{reset} {msg}"


def setup_logger(timestamps=False, debug=False):
    logger = logging.getLogger("bigpotam")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter(timestamps=timestamps))
    logger.addHandler(handler)

    return logger


def success(logger, msg, *args, **kwargs):
    logger.log(ColorFormatter.SUCCESS, msg, *args, **kwargs)
