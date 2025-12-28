"""
Error Handling and Custom Exceptions Module

Defines all custom exceptions used throughout the application with proper
error context and recovery guidance.

Author: Security Team
Version: 1.0.0
"""

from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class CyberGuardException(Exception):
    """
    Base exception class for all CyberGuard exceptions.
    
    Provides structured error handling with error codes, context, and recovery suggestions.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "INTERNAL_ERROR",
        status_code: int = 500,
        context: Optional[Dict[str, Any]] = None,
        recovery_suggestions: Optional[str] = None
    ):
        """
        Initialize exception with structured error information.
        
        Args:
            message: Human-readable error message
            error_code: Machine-readable error code for categorization
            status_code: HTTP status code to return to client
            context: Additional context data for debugging
            recovery_suggestions: Helpful suggestions for recovery
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.context = context or {}
        self.recovery_suggestions = recovery_suggestions

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON response."""
        return {
            'error': self.error_code,
            'message': self.message,
            'context': self.context,
            'recovery': self.recovery_suggestions,
        }

    def log_error(self) -> None:
        """Log error with full context."""
        logger.error(
            f"{self.error_code}: {self.message}",
            extra={
                'error_code': self.error_code,
                'status_code': self.status_code,
                'context': self.context,
            }
        )


# ═══════════════════════════════════════════════════════════════════════════
# URL VALIDATION AND PROCESSING EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════


class URLValidationError(CyberGuardException):
    """Raised when URL validation fails."""

    def __init__(self, message: str, url: Optional[str] = None):
        super().__init__(
            message=message,
            error_code="URL_VALIDATION_ERROR",
            status_code=400,
            context={'url': url} if url else {},
            recovery_suggestions="Ensure the URL is valid, accessible, and uses http:// or https://"
        )


class URLNotAccessibleError(CyberGuardException):
    """Raised when URL cannot be accessed."""

    def __init__(self, url: str, reason: str):
        super().__init__(
            message=f"Unable to access URL: {reason}",
            error_code="URL_NOT_ACCESSIBLE",
            status_code=400,
            context={'url': url, 'reason': reason},
            recovery_suggestions="Check if the URL is reachable and not blocked by firewall"
        )


class URLMalformedError(CyberGuardException):
    """Raised when URL format is invalid."""

    def __init__(self, url: str, reason: str):
        super().__init__(
            message=f"URL is malformed: {reason}",
            error_code="URL_MALFORMED",
            status_code=400,
            context={'url': url},
            recovery_suggestions="Ensure the URL follows the format: https://example.com"
        )


class PrivateIPError(CyberGuardException):
    """Raised when attempting to scan private IP addresses."""

    def __init__(self, ip: str):
        super().__init__(
            message=f"Scanning private IP addresses is not allowed: {ip}",
            error_code="PRIVATE_IP_BLOCKED",
            status_code=403,
            context={'ip': ip},
            recovery_suggestions="Use a public IP address or domain name"
        )


class URLLengthExceededError(CyberGuardException):
    """Raised when URL exceeds maximum length."""

    def __init__(self, url: str, max_length: int):
        super().__init__(
            message=f"URL length ({len(url)}) exceeds maximum ({max_length})",
            error_code="URL_LENGTH_EXCEEDED",
            status_code=400,
            context={'url_length': len(url), 'max_length': max_length},
            recovery_suggestions="Use a shorter URL or contact support"
        )


class URLInjectionError(CyberGuardException):
    """Raised when URL contains potential injection attack patterns."""

    def __init__(self, url: str, pattern: str):
        super().__init__(
            message="URL contains potentially malicious patterns",
            error_code="URL_INJECTION_DETECTED",
            status_code=400,
            context={'url': url, 'pattern': pattern},
            recovery_suggestions="Ensure the URL does not contain suspicious characters"
        )


# ═══════════════════════════════════════════════════════════════════════════
# API AND NETWORK EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════


class APIError(CyberGuardException):
    """Base exception for API-related errors."""

    def __init__(
        self,
        message: str,
        api_name: str,
        status_code: int = 500,
        response_status: Optional[int] = None,
        recovery_suggestions: Optional[str] = None
    ):
        super().__init__(
            message=f"{api_name} API error: {message}",
            error_code="API_ERROR",
            status_code=status_code,
            context={'api': api_name, 'response_status': response_status},
            recovery_suggestions=recovery_suggestions or f"Check {api_name} API status and retry"
        )


class APITimeoutError(CyberGuardException):
    """Raised when API request times out."""

    def __init__(self, api_name: str, timeout_seconds: int):
        super().__init__(
            message=f"{api_name} request timed out after {timeout_seconds} seconds",
            error_code="API_TIMEOUT",
            status_code=504,
            context={'api': api_name, 'timeout': timeout_seconds},
            recovery_suggestions=f"Increase timeout or retry later. {api_name} may be under high load"
        )


class APIConnectionError(CyberGuardException):
    """Raised when API connection fails."""

    def __init__(self, api_name: str, reason: str):
        super().__init__(
            message=f"Failed to connect to {api_name}: {reason}",
            error_code="API_CONNECTION_ERROR",
            status_code=503,
            context={'api': api_name, 'reason': reason},
            recovery_suggestions=f"Check {api_name} API availability and network connectivity"
        )


class RateLimitExceededError(CyberGuardException):
    """Raised when API rate limit is exceeded."""

    def __init__(self, api_name: str, retry_after_seconds: Optional[int] = None):
        super().__init__(
            message=f"Rate limit exceeded for {api_name}",
            error_code="RATE_LIMIT_EXCEEDED",
            status_code=429,
            context={'api': api_name, 'retry_after': retry_after_seconds},
            recovery_suggestions=f"Retry after {retry_after_seconds or 60} seconds"
        )


class APIAuthenticationError(CyberGuardException):
    """Raised when API authentication fails."""

    def __init__(self, api_name: str):
        super().__init__(
            message=f"Failed to authenticate with {api_name}",
            error_code="API_AUTHENTICATION_ERROR",
            status_code=401,
            context={'api': api_name},
            recovery_suggestions=f"Check {api_name} API key configuration"
        )


# ═══════════════════════════════════════════════════════════════════════════
# THREAT DETECTION AND ANALYSIS EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════


class ThreatAnalysisError(CyberGuardException):
    """Raised when threat analysis fails."""

    def __init__(self, message: str, component: str):
        super().__init__(
            message=f"Threat analysis failed in {component}: {message}",
            error_code="THREAT_ANALYSIS_ERROR",
            status_code=500,
            context={'component': component},
            recovery_suggestions="Retry the scan or contact support"
        )


class LLMAnalysisError(CyberGuardException):
    """Raised when LLM-based analysis fails."""

    def __init__(self, message: str, reason: str):
        super().__init__(
            message=f"LLM analysis failed: {message}",
            error_code="LLM_ANALYSIS_ERROR",
            status_code=500,
            context={'reason': reason},
            recovery_suggestions="Retrying with fallback analysis method"
        )


class LLMAnalysisFallback(Exception):
    """Indicates LLM analysis failed and fallback was used."""

    def __init__(self, message: str, fallback_used: str):
        self.message = message
        self.fallback_used = fallback_used
        logger.warning(f"LLM analysis failed, using fallback: {fallback_used}")


class MLModelError(CyberGuardException):
    """Raised when ML model prediction fails."""

    def __init__(self, message: str, model_name: str):
        super().__init__(
            message=f"ML model error ({model_name}): {message}",
            error_code="ML_MODEL_ERROR",
            status_code=500,
            context={'model': model_name},
            recovery_suggestions="Check ML model files and retrain if necessary"
        )


class NoThreatsDetectedError(CyberGuardException):
    """Raised when no threat detection services are available."""

    def __init__(self):
        super().__init__(
            message="No threat detection services available",
            error_code="NO_SERVICES_AVAILABLE",
            status_code=503,
            recovery_suggestions="Configure and enable threat intelligence services"
        )


# ═══════════════════════════════════════════════════════════════════════════
# DNS AND DOMAIN LOOKUP EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════


class DNSLookupError(CyberGuardException):
    """Raised when DNS lookup fails."""

    def __init__(self, domain: str, reason: str):
        super().__init__(
            message=f"DNS lookup failed for {domain}: {reason}",
            error_code="DNS_LOOKUP_ERROR",
            status_code=400,
            context={'domain': domain, 'reason': reason},
            recovery_suggestions="Check domain name and network connectivity"
        )


class WHOISLookupError(CyberGuardException):
    """Raised when WHOIS lookup fails."""

    def __init__(self, domain: str, reason: str):
        super().__init__(
            message=f"WHOIS lookup failed for {domain}: {reason}",
            error_code="WHOIS_LOOKUP_ERROR",
            status_code=400,
            context={'domain': domain, 'reason': reason},
            recovery_suggestions="Domain may not be registered or WHOIS service may be unavailable"
        )


# ═══════════════════════════════════════════════════════════════════════════
# CACHING AND STORAGE EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════


class CacheError(CyberGuardException):
    """Raised when cache operation fails."""

    def __init__(self, message: str, operation: str):
        super().__init__(
            message=f"Cache {operation} failed: {message}",
            error_code="CACHE_ERROR",
            status_code=500,
            context={'operation': operation},
            recovery_suggestions="Cache will be cleared and rebuilt"
        )


class StorageError(CyberGuardException):
    """Raised when data storage operation fails."""

    def __init__(self, message: str, operation: str):
        super().__init__(
            message=f"Storage {operation} failed: {message}",
            error_code="STORAGE_ERROR",
            status_code=500,
            context={'operation': operation},
            recovery_suggestions="Check disk space and permissions"
        )


# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND INITIALIZATION EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════


class ConfigurationError(CyberGuardException):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, setting: Optional[str] = None):
        super().__init__(
            message=f"Configuration error: {message}",
            error_code="CONFIGURATION_ERROR",
            status_code=500,
            context={'setting': setting} if setting else {},
            recovery_suggestions="Check environment variables and configuration files"
        )


class InitializationError(CyberGuardException):
    """Raised when service initialization fails."""

    def __init__(self, service_name: str, reason: str):
        super().__init__(
            message=f"Failed to initialize {service_name}: {reason}",
            error_code="INITIALIZATION_ERROR",
            status_code=500,
            context={'service': service_name},
            recovery_suggestions=f"Check {service_name} dependencies and configuration"
        )


# ═══════════════════════════════════════════════════════════════════════════
# RATE LIMITING AND ABUSE PREVENTION EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════


class RateLimitError(CyberGuardException):
    """Raised when user exceeds rate limits."""

    def __init__(self, limit_type: str, retry_after_seconds: int):
        super().__init__(
            message=f"Rate limit exceeded: {limit_type}",
            error_code="RATE_LIMIT_ERROR",
            status_code=429,
            context={'limit_type': limit_type, 'retry_after': retry_after_seconds},
            recovery_suggestions=f"Retry after {retry_after_seconds} seconds"
        )


class AbuseDetectedError(CyberGuardException):
    """Raised when potential abuse is detected."""

    def __init__(self, reason: str, user_id: Optional[str] = None):
        super().__init__(
            message=f"Potential abuse detected: {reason}",
            error_code="ABUSE_DETECTED",
            status_code=403,
            context={'reason': reason, 'user_id': user_id},
            recovery_suggestions="Your access may be temporarily restricted"
        )


def handle_exception(exc: Exception) -> Dict[str, Any]:
    """
    Convert any exception to standardized error response.
    
    Args:
        exc: Exception to handle
        
    Returns:
        Dictionary with error information suitable for API response
    """
    if isinstance(exc, CyberGuardException):
        exc.log_error()
        return {
            'success': False,
            'error': exc.to_dict(),
            'status_code': exc.status_code,
        }
    else:
        logger.exception(f"Unhandled exception: {exc}")
        return {
            'success': False,
            'error': {
                'error': 'INTERNAL_ERROR',
                'message': 'An unexpected error occurred',
                'context': {},
            },
            'status_code': 500,
        }
