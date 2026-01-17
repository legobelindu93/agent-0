import logging
import json
import os
from logging.handlers import RotatingFileHandler
from config import LOG_DIR, LOG_FILE, MAX_LOG_SIZE, BACKUP_COUNT

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "alert_type": getattr(record, "alert_type", "GENERIC"),
            "score": getattr(record, "score", 0),
            "details": getattr(record, "details", {})
        }
        return json.dumps(log_record)

class Logger:
    def __init__(self):
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        
        self.logger = logging.getLogger("SecurityAgent")
        self.logger.setLevel(logging.INFO)
        
        log_path = os.path.join(LOG_DIR, LOG_FILE)
        handler = RotatingFileHandler(log_path, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT)
        handler.setFormatter(JsonFormatter())
        
        self.logger.addHandler(handler)

    def log_event(self, level, message, alert_type="GENERIC", score=0, details=None):
        extra = {
            "alert_type": alert_type,
            "score": score,
            "details": details or {}
        }
        if level == "INFO":
            self.logger.info(message, extra=extra)
        elif level == "WARNING":
            self.logger.warning(message, extra=extra)
        elif level == "CRITICAL":
            self.logger.critical(message, extra=extra)
        elif level == "ERROR":
            self.logger.error(message, extra=extra)

# Instance globale
# local_logger = Logger() 
# Evitons le nom logger qui rentre en conflit avec le module logging
agent_logger = Logger()
