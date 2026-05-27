import logging
import os
from logging.handlers import RotatingFileHandler

# Ensure log directory exists
os.makedirs("logs", exist_ok=True)

# Define precise formatting including the mandatory trace_id
LOG_FORMAT = "%(asctime)s [%(levelname)s] [TRACE:%(trace_id)s] %(message)s"

class TraceFilter(logging.Filter):
    """Ensures trace_id is always present in log records to prevent formatting crashes."""
    def filter(self, record):
        if not hasattr(record, "trace_id"):
            record.trace_id = "SYSTEM"
        return True

def setup_logger(name: str, log_file: str, level=logging.INFO) -> logging.Logger:
    """Creates a high-performance rotating log handler."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    # Prevent duplicate handlers on reload
    if not logger.handlers:
        handler = RotatingFileHandler(
            os.path.join("logs", log_file),
            maxBytes=50 * 1024 * 1024,  # 50MB per log file
            backupCount=10,
            encoding="utf-8"
        )
        formatter = logging.Formatter(LOG_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.addFilter(TraceFilter())

    return logger

# Initialize the three mandatory independent log streams
access_logger = setup_logger("access", "access.log")
error_logger = setup_logger("error", "error.log", logging.ERROR)
security_logger = setup_logger("security", "security.log", logging.WARNING)
