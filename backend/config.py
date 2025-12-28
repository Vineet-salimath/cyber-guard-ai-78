"""
Configuration Management Module

Centralized configuration management with environment validation and security defaults.
Ensures all configuration values are properly validated and secure.

Author: Security Team
Version: 1.0.0
"""

import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class ConfigurationError(Exception):
    """Raised when configuration validation fails."""
    pass


class Config:
    """
    Production-ready configuration management class.
    
    Loads and validates all environment variables with sensible defaults.
    Implements type checking and security validation for sensitive values.
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE APPLICATION SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    DEBUG: bool = os.getenv('DEBUG', 'False').lower() == 'true'
    ENV: str = os.getenv('ENVIRONMENT', 'production')
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    
    # Application paths
    BASE_DIR: Path = Path(__file__).parent
    LOG_DIR: Path = BASE_DIR / 'logs'
    DATA_DIR: Path = BASE_DIR / 'data'
    CACHE_DIR: Path = BASE_DIR / 'cache'
    AUDIT_LOG_DIR: Path = BASE_DIR / 'audit_logs'

    # ═══════════════════════════════════════════════════════════════════════════
    # API TIMEOUT AND CONNECTION SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    # URL scanning timeouts (in seconds)
    REQUEST_TIMEOUT: int = int(os.getenv('REQUEST_TIMEOUT', '10'))
    CONNECT_TIMEOUT: int = int(os.getenv('CONNECT_TIMEOUT', '5'))
    READ_TIMEOUT: int = int(os.getenv('READ_TIMEOUT', '8'))
    
    # URL scanning limits
    MAX_URLS_PER_REQUEST: int = int(os.getenv('MAX_URLS_PER_REQUEST', '10'))
    MAX_CONCURRENT_SCANS: int = int(os.getenv('MAX_CONCURRENT_SCANS', '5'))
    
    # Connection pooling
    CONNECTION_POOL_SIZE: int = int(os.getenv('CONNECTION_POOL_SIZE', '20'))
    POOL_CONNECTIONS: int = int(os.getenv('POOL_CONNECTIONS', '10'))
    POOL_MAXSIZE: int = int(os.getenv('POOL_MAXSIZE', '20'))

    # ═══════════════════════════════════════════════════════════════════════════
    # RATE LIMITING SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    # Rate limiting (requests per minute per API)
    RATE_LIMIT_REQUESTS: int = int(os.getenv('RATE_LIMIT_REQUESTS', '100'))
    RATE_LIMIT_WINDOW: int = int(os.getenv('RATE_LIMIT_WINDOW', '60'))  # seconds
    
    # API-specific rate limits
    VIRUSTOTAL_RATE_LIMIT: int = int(os.getenv('VIRUSTOTAL_RATE_LIMIT', '4'))  # requests/min
    URLSCAN_RATE_LIMIT: int = int(os.getenv('URLSCAN_RATE_LIMIT', '60'))
    WHOIS_RATE_LIMIT: int = int(os.getenv('WHOIS_RATE_LIMIT', '50'))

    # ═══════════════════════════════════════════════════════════════════════════
    # CACHING SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    ENABLE_CACHE: bool = os.getenv('ENABLE_CACHE', 'True').lower() == 'true'
    CACHE_TTL_HOURS: int = int(os.getenv('CACHE_TTL_HOURS', '24'))
    CACHE_MAX_SIZE_MB: int = int(os.getenv('CACHE_MAX_SIZE_MB', '500'))
    
    # DNS cache TTL
    DNS_CACHE_TTL: int = int(os.getenv('DNS_CACHE_TTL', '3600'))  # 1 hour
    
    # WHOIS cache TTL
    WHOIS_CACHE_TTL: int = int(os.getenv('WHOIS_CACHE_TTL', '604800'))  # 7 days

    # ═══════════════════════════════════════════════════════════════════════════
    # THREAT INTELLIGENCE API KEYS
    # ═══════════════════════════════════════════════════════════════════════════

    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv('VIRUSTOTAL_API_KEY')
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv('ABUSEIPDB_API_KEY')
    ALIENVAULT_OTX_KEY: Optional[str] = os.getenv('ALIENVAULT_OTX_KEY')
    URLSCAN_API_KEY: Optional[str] = os.getenv('URLSCAN_API_KEY')
    A2A_API_KEY: Optional[str] = os.getenv('A2A_API_KEY')
    PLEXIGLASS_API_KEY: Optional[str] = os.getenv('PLEXIGLASS_API_KEY')

    # ═══════════════════════════════════════════════════════════════════════════
    # A2A AND PLEXIGLASS SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    A2A_BASE_URL: str = os.getenv('A2A_BASE_URL', 'https://api.a2a.io/v1')
    A2A_DEV_MODE: bool = os.getenv('A2A_DEV_MODE', 'False').lower() == 'true'
    A2A_TIMEOUT: int = int(os.getenv('A2A_TIMEOUT', '10'))
    
    PLEXIGLASS_BASE_URL: str = os.getenv('PLEXIGLASS_BASE_URL', 'https://api.plexiglass.io/v1')
    PLEXIGLASS_TIMEOUT: int = int(os.getenv('PLEXIGLASS_TIMEOUT', '10'))

    # ═══════════════════════════════════════════════════════════════════════════
    # LLM ANALYSIS SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    ENABLE_LLM_ANALYSIS: bool = os.getenv('ENABLE_LLM_ANALYSIS', 'True').lower() == 'true'
    LLM_API_KEY: Optional[str] = os.getenv('LLM_API_KEY')
    LLM_MODEL: str = os.getenv('LLM_MODEL', 'gpt-3.5-turbo')
    LLM_TIMEOUT: int = int(os.getenv('LLM_TIMEOUT', '15'))
    LLM_MAX_RETRIES: int = int(os.getenv('LLM_MAX_RETRIES', '3'))

    # ═══════════════════════════════════════════════════════════════════════════
    # LOGGING SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    LOG_TO_FILE: bool = os.getenv('LOG_TO_FILE', 'True').lower() == 'true'
    LOG_TO_CONSOLE: bool = os.getenv('LOG_TO_CONSOLE', 'True').lower() == 'true'
    LOG_FORMAT: str = os.getenv('LOG_FORMAT', 
                                 '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Max log file size (MB)
    LOG_MAX_SIZE: int = int(os.getenv('LOG_MAX_SIZE', '100'))
    # Number of log file backups
    LOG_BACKUP_COUNT: int = int(os.getenv('LOG_BACKUP_COUNT', '5'))

    # ═══════════════════════════════════════════════════════════════════════════
    # AUDIT LOGGING SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    ENABLE_AUDIT_LOG: bool = os.getenv('ENABLE_AUDIT_LOG', 'True').lower() == 'true'
    AUDIT_LOG_RETENTION_DAYS: int = int(os.getenv('AUDIT_LOG_RETENTION_DAYS', '90'))

    # ═══════════════════════════════════════════════════════════════════════════
    # DATABASE SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    DATABASE_URL: str = os.getenv('DATABASE_URL', 'sqlite:///scan_results.db')
    DATABASE_POOL_SIZE: int = int(os.getenv('DATABASE_POOL_SIZE', '5'))

    # ═══════════════════════════════════════════════════════════════════════════
    # SECURITY SETTINGS
    # ═══════════════════════════════════════════════════════════════════════════

    # Maximum URL length to scan (prevent ReDoS attacks)
    MAX_URL_LENGTH: int = int(os.getenv('MAX_URL_LENGTH', '2083'))
    
    # Allowed URL schemes (whitelist)
    ALLOWED_URL_SCHEMES: tuple = ('http', 'https')
    
    # Block private/internal IP ranges
    BLOCK_PRIVATE_IPS: bool = os.getenv('BLOCK_PRIVATE_IPS', 'True').lower() == 'true'
    
    # Enable CORS
    CORS_ORIGINS: str = os.getenv('CORS_ORIGINS', '*')

    # ═══════════════════════════════════════════════════════════════════════════
    # FEATURE FLAGS
    # ═══════════════════════════════════════════════════════════════════════════

    ENABLE_VIRUSTOTAL: bool = os.getenv('ENABLE_VIRUSTOTAL', 'True').lower() == 'true'
    ENABLE_URLSCAN: bool = os.getenv('ENABLE_URLSCAN', 'True').lower() == 'true'
    ENABLE_A2A: bool = os.getenv('ENABLE_A2A', 'False').lower() == 'true'
    ENABLE_PLEXIGLASS: bool = os.getenv('ENABLE_PLEXIGLASS', 'False').lower() == 'true'
    ENABLE_ML_ANALYSIS: bool = os.getenv('ENABLE_ML_ANALYSIS', 'True').lower() == 'true'
    ENABLE_WHOIS_LOOKUP: bool = os.getenv('ENABLE_WHOIS_LOOKUP', 'True').lower() == 'true'
    ENABLE_DNS_LOOKUP: bool = os.getenv('ENABLE_DNS_LOOKUP', 'True').lower() == 'true'

    @classmethod
    def validate(cls) -> None:
        """
        Validate all configuration settings.
        
        Raises:
            ConfigurationError: If critical configuration is missing or invalid.
        """
        errors: List[str] = []

        # Create required directories
        for directory in [cls.LOG_DIR, cls.DATA_DIR, cls.CACHE_DIR, cls.AUDIT_LOG_DIR]:
            directory.mkdir(parents=True, exist_ok=True)

        # Validate timeouts
        if cls.REQUEST_TIMEOUT <= 0:
            errors.append(f"REQUEST_TIMEOUT must be positive, got {cls.REQUEST_TIMEOUT}")
        
        if cls.CONNECT_TIMEOUT > cls.REQUEST_TIMEOUT:
            errors.append(f"CONNECT_TIMEOUT ({cls.CONNECT_TIMEOUT}) exceeds REQUEST_TIMEOUT ({cls.REQUEST_TIMEOUT})")

        # Validate rate limits
        if cls.RATE_LIMIT_REQUESTS <= 0:
            errors.append(f"RATE_LIMIT_REQUESTS must be positive, got {cls.RATE_LIMIT_REQUESTS}")
        
        if cls.RATE_LIMIT_WINDOW <= 0:
            errors.append(f"RATE_LIMIT_WINDOW must be positive, got {cls.RATE_LIMIT_WINDOW}")

        # Validate cache settings
        if cls.CACHE_TTL_HOURS < 0:
            errors.append(f"CACHE_TTL_HOURS cannot be negative, got {cls.CACHE_TTL_HOURS}")

        # Validate URL limits
        if cls.MAX_URL_LENGTH <= 0:
            errors.append(f"MAX_URL_LENGTH must be positive, got {cls.MAX_URL_LENGTH}")
        
        if cls.MAX_URLS_PER_REQUEST <= 0:
            errors.append(f"MAX_URLS_PER_REQUEST must be positive, got {cls.MAX_URLS_PER_REQUEST}")

        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ConfigurationError(error_msg)

    @classmethod
    def get_api_keys(cls) -> Dict[str, Optional[str]]:
        """
        Get all configured API keys for threat intelligence services.
        
        Returns:
            Dictionary with API keys for all services.
        """
        return {
            'virustotal': cls.VIRUSTOTAL_API_KEY,
            'abuseipdb': cls.ABUSEIPDB_API_KEY,
            'alienvault_otx': cls.ALIENVAULT_OTX_KEY,
            'urlscan': cls.URLSCAN_API_KEY,
            'a2a': cls.A2A_API_KEY,
            'plexiglass': cls.PLEXIGLASS_API_KEY,
        }

    @classmethod
    def get_enabled_services(cls) -> Dict[str, bool]:
        """
        Get which threat intelligence services are enabled.
        
        Returns:
            Dictionary with service enablement status.
        """
        return {
            'virustotal': cls.ENABLE_VIRUSTOTAL and bool(cls.VIRUSTOTAL_API_KEY),
            'urlscan': cls.ENABLE_URLSCAN and bool(cls.URLSCAN_API_KEY),
            'a2a': cls.ENABLE_A2A and bool(cls.A2A_API_KEY),
            'plexiglass': cls.ENABLE_PLEXIGLASS and bool(cls.PLEXIGLASS_API_KEY),
            'ml_analysis': cls.ENABLE_ML_ANALYSIS,
            'whois_lookup': cls.ENABLE_WHOIS_LOOKUP,
            'dns_lookup': cls.ENABLE_DNS_LOOKUP,
        }

    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """
        Export configuration as dictionary (excluding sensitive values).
        
        Returns:
            Configuration dictionary with sensitive values masked.
        """
        config_dict = {}
        for key in dir(cls):
            if not key.startswith('_') and key.isupper():
                value = getattr(cls, key)
                # Mask API keys
                if 'KEY' in key or 'TOKEN' in key:
                    value = '***REDACTED***' if value else None
                elif isinstance(value, (str, int, bool, float, type(None))):
                    config_dict[key] = value
        
        return config_dict


# Validate configuration on import
try:
    Config.validate()
    logger = logging.getLogger(__name__)
    logger.info("Configuration validation passed")
except ConfigurationError as e:
    print(f"❌ Configuration Error: {e}")
    raise
