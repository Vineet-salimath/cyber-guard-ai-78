"""
Logging Configuration Module

Sets up structured logging with file rotation, console output, and performance tracking.
All logs are written to files for auditing and debugging purposes.

Author: Security Team
Version: 1.0.0
"""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional
import sys
from datetime import datetime

from config import Config


class ColoredFormatter(logging.Formatter):
    """
    Colored log formatter for console output.
    
    Adds color codes to log messages for better readability in terminal.
    """

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[41m',   # Red background
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with color codes."""
        color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(logger_name: str = __name__) -> logging.Logger:
    """
    Configure structured logging for the application.
    
    Sets up:
    - File logging with rotation (100MB per file, 5 backups)
    - Console logging with color formatting
    - Proper log levels and formatting
    
    Args:
        logger_name: Name of the logger
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(logger_name)
    
    # Only configure once
    if logger.handlers:
        return logger
    
    # Set log level
    log_level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Create logs directory if needed
    Config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FILE HANDLER - Rotating file handler
    # ═══════════════════════════════════════════════════════════════════════════
    
    if Config.LOG_TO_FILE:
        log_file = Config.LOG_DIR / f"{logger_name}.log"
        
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=Config.LOG_MAX_SIZE * 1024 * 1024,  # Convert MB to bytes
            backupCount=Config.LOG_BACKUP_COUNT,
            encoding='utf-8'
        )
        file_handler.setLevel(log_level)
        
        # File formatter with full details
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # CONSOLE HANDLER - Console output with colors
    # ═══════════════════════════════════════════════════════════════════════════
    
    if Config.LOG_TO_CONSOLE:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        
        # Console formatter with colors
        console_formatter = ColoredFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured logger instance
    """
    return setup_logging(name)


class PerformanceLogger:
    """
    Context manager for tracking performance metrics.
    
    Usage:
        with PerformanceLogger('API_Call', 'VirusTotal'):
            # Code being timed
            api_result = virustotal.scan(url)
    """

    def __init__(self, operation: str, service: Optional[str] = None):
        """
        Initialize performance logger.
        
        Args:
            operation: Name of the operation being timed
            service: Optional service name
        """
        self.operation = operation
        self.service = service or 'Internal'
        self.logger = get_logger(__name__)
        self.start_time: Optional[float] = None

    def __enter__(self):
        """Start timing."""
        import time
        self.start_time = time.time()
        self.logger.debug(f"Starting {self.operation} ({self.service})")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Log elapsed time."""
        import time
        
        if self.start_time is None:
            return
        
        elapsed = time.time() - self.start_time
        
        if exc_type is not None:
            self.logger.error(
                f"{self.operation} ({self.service}) failed after {elapsed:.2f}s: {exc_val}"
            )
        else:
            if elapsed > 5:
                self.logger.warning(
                    f"{self.operation} ({self.service}) took {elapsed:.2f}s (slow)"
                )
            else:
                self.logger.info(
                    f"{self.operation} ({self.service}) completed in {elapsed:.2f}s"
                )


class AuditLogger:
    """
    Specialized logger for security audit events.
    
    Tracks all security-relevant operations including:
    - URL scans
    - API calls
    - Authentication events
    - Permission checks
    - Error conditions
    
    All audit events are written to a separate audit log file.
    """

    def __init__(self):
        """Initialize audit logger."""
        self.logger = logging.getLogger('audit')
        
        # Configure audit logger if not already done
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            
            # Create audit logs directory
            Config.AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
            
            # Rotating file handler for audit log
            audit_log_file = Config.AUDIT_LOG_DIR / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
            audit_handler = logging.handlers.RotatingFileHandler(
                filename=audit_log_file,
                maxBytes=100 * 1024 * 1024,  # 100MB
                backupCount=Config.AUDIT_LOG_RETENTION_DAYS,
                encoding='utf-8'
            )
            
            # JSON-like format for structured audit logs
            audit_formatter = logging.Formatter(
                '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            audit_handler.setFormatter(audit_formatter)
            self.logger.addHandler(audit_handler)

    def log_scan(
        self,
        url: str,
        user_id: Optional[str],
        verdict: str,
        risk_score: float,
        duration_seconds: float
    ) -> None:
        """
        Log URL scan event.
        
        Args:
            url: Scanned URL
            user_id: User performing scan
            verdict: Scan verdict (safe/suspicious/malicious)
            risk_score: Risk score (0-100)
            duration_seconds: Scan duration
        """
        self.logger.info(
            f"URL_SCAN | url={url[:100]} | user={user_id} | "
            f"verdict={verdict} | risk_score={risk_score} | duration={duration_seconds:.2f}s"
        )

    def log_api_call(
        self,
        api_name: str,
        endpoint: str,
        status_code: Optional[int] = None,
        duration_seconds: float = 0.0,
        error: Optional[str] = None
    ) -> None:
        """
        Log external API call.
        
        Args:
            api_name: API name (VirusTotal, UrlScan, etc.)
            endpoint: API endpoint called
            status_code: HTTP response status code
            duration_seconds: Request duration
            error: Error message if failed
        """
        status = "SUCCESS" if status_code and 200 <= status_code < 300 else "FAILURE"
        error_msg = f" | error={error}" if error else ""
        
        self.logger.info(
            f"API_CALL | api={api_name} | endpoint={endpoint} | "
            f"status={status_code} | result={status} | duration={duration_seconds:.2f}s{error_msg}"
        )

    def log_security_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        details: Optional[dict] = None
    ) -> None:
        """
        Log security event.
        
        Args:
            event_type: Type of security event
            severity: Severity level (info/warning/critical)
            description: Event description
            details: Additional event details
        """
        details_str = f" | details={details}" if details else ""
        self.logger.warning(
            f"SECURITY_EVENT | type={event_type} | severity={severity} | {description}{details_str}"
        )

    def log_error(
        self,
        component: str,
        error_type: str,
        error_message: str,
        context: Optional[dict] = None
    ) -> None:
        """
        Log error event.
        
        Args:
            component: Component where error occurred
            error_type: Type of error
            error_message: Error message
            context: Additional context
        """
        context_str = f" | context={context}" if context else ""
        self.logger.error(
            f"ERROR | component={component} | type={error_type} | msg={error_message}{context_str}"
        )

    def log_rate_limit(
        self,
        api_name: str,
        limit_type: str,
        current_count: int,
        max_allowed: int
    ) -> None:
        """
        Log rate limiting event.
        
        Args:
            api_name: API being rate limited
            limit_type: Type of limit (request, concurrent, etc.)
            current_count: Current usage count
            max_allowed: Maximum allowed
        """
        self.logger.warning(
            f"RATE_LIMIT | api={api_name} | type={limit_type} | "
            f"usage={current_count}/{max_allowed}"
        )


# Global audit logger instance
audit_logger = AuditLogger()


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    return audit_logger
