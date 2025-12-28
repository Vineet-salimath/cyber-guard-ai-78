"""
Threat Intelligence API Client Module

Unified client for A2A, Plexiglass, and other threat intelligence APIs.
Implements retry logic, timeout handling, error recovery, and rate limiting.

Features:
- Automatic retry with exponential backoff
- Request/response logging
- Rate limit handling
- Timeout management (5-10 seconds per URL)
- Connection pooling
- Development mode for A2A testing

Author: Security Team
Version: 1.0.0
"""

import logging
import time
from typing import Dict, Any, Optional, List, Tuple
from functools import wraps
from datetime import datetime, timedelta
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from config import Config
from error_handler import (
    APIError,
    APITimeoutError,
    APIConnectionError,
    APIAuthenticationError,
    RateLimitExceededError,
)
from performance_cache import get_rate_limiter, api_cache
from logging_config import get_logger, PerformanceLogger, get_audit_logger

logger = get_logger(__name__)
audit_logger = get_audit_logger()


class ThreatIntelligenceAPIClient:
    """
    Unified threat intelligence API client.
    
    Handles communication with external threat intelligence services
    including A2A, Plexiglass, VirusTotal, URLScan, etc.
    
    Provides:
    - Automatic retries with exponential backoff
    - Rate limiting
    - Timeout handling
    - Request/response logging
    - Error recovery
    - Caching integration
    """

    def __init__(self, api_name: str, api_key: Optional[str] = None):
        """
        Initialize API client.
        
        Args:
            api_name: Name of API service
            api_key: API key for authentication
            
        Raises:
            APIAuthenticationError: If API key not provided and required
        """
        self.api_name = api_name
        self.api_key = api_key
        self.session = self._create_session()
        
        # Get API-specific configuration
        self.base_url = self._get_base_url()
        self.timeout = self._get_timeout()
        self.max_retries = Config.LLM_MAX_RETRIES
        
        logger.info(f"Initialized {api_name} API client")

    def _get_base_url(self) -> str:
        """Get base URL for API."""
        if self.api_name.lower() == 'a2a':
            return Config.A2A_BASE_URL
        elif self.api_name.lower() == 'plexiglass':
            return Config.PLEXIGLASS_BASE_URL
        else:
            return f"https://api.{self.api_name.lower()}.io/v1"

    def _get_timeout(self) -> Tuple[float, float]:
        """Get timeout configuration for API."""
        if self.api_name.lower() == 'a2a':
            timeout = Config.A2A_TIMEOUT
        elif self.api_name.lower() == 'plexiglass':
            timeout = Config.PLEXIGLASS_TIMEOUT
        else:
            timeout = Config.REQUEST_TIMEOUT
        
        return (Config.CONNECT_TIMEOUT, timeout)

    def _create_session(self) -> requests.Session:
        """
        Create requests session with connection pooling and retry strategy.
        
        Returns:
            Configured requests.Session
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=0.5,  # Exponential backoff: 0.5s, 1s, 2s...
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["GET", "POST", "PUT"],
            raise_on_status=False
        )
        
        # Mount retry strategy for both http and https
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=Config.POOL_CONNECTIONS,
            pool_maxsize=Config.POOL_MAXSIZE
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update(self._get_headers())
        
        return session

    def _get_headers(self) -> Dict[str, str]:
        """
        Get headers for API requests.
        
        Returns:
            Headers dictionary
        """
        headers = {
            'User-Agent': 'CyberGuard-AI/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        
        # Add authentication headers
        if self.api_key:
            if self.api_name.lower() in ['virustotal', 'a2a', 'plexiglass']:
                headers['X-API-Key'] = self.api_key
            elif self.api_name.lower() == 'urlscan':
                headers['API-Key'] = self.api_key
            elif self.api_name.lower() in ['abuseipdb', 'alienvault']:
                headers['Authorization'] = f"Bearer {self.api_key}"
        
        return headers

    def _handle_response_error(self, response: requests.Response) -> None:
        """
        Handle API response errors.
        
        Args:
            response: Response object
            
        Raises:
            APIAuthenticationError: 401/403
            RateLimitExceededError: 429
            APIError: Other errors
        """
        status_code = response.status_code
        
        try:
            body = response.json()
        except:
            body = response.text
        
        if status_code == 401:
            raise APIAuthenticationError(self.api_name)
        
        elif status_code == 403:
            raise APIAuthenticationError(self.api_name)
        
        elif status_code == 429:
            # Rate limit exceeded
            retry_after = response.headers.get('Retry-After', '60')
            try:
                retry_seconds = int(retry_after)
            except:
                retry_seconds = 60
            
            audit_logger.log_rate_limit(
                self.api_name,
                'rate_limit',
                1,
                1  # Placeholder
            )
            raise RateLimitExceededError(self.api_name, retry_seconds)
        
        elif status_code == 504:
            raise APITimeoutError(self.api_name, self.timeout[1])
        
        else:
            raise APIError(
                message=f"API error: {status_code}",
                api_name=self.api_name,
                status_code=status_code,
                response_status=status_code,
                recovery_suggestions=f"Check {self.api_name} status and try again"
            )

    def _retry_with_backoff(
        self,
        func,
        *args,
        **kwargs
    ) -> Any:
        """
        Retry function with exponential backoff.
        
        Args:
            func: Function to call
            args: Function arguments
            kwargs: Function keyword arguments
            
        Returns:
            Function result
            
        Raises:
            APIError: If all retries exhausted
        """
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            
            except (APITimeoutError, APIConnectionError) as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.warning(
                        f"{self.api_name} attempt {attempt + 1} failed, "
                        f"retrying in {wait_time}s: {e.message}"
                    )
                    time.sleep(wait_time)
            
            except APIError as e:
                raise  # Don't retry on other API errors
        
        if last_error:
            raise last_error
        
        raise APIError(
            message="Max retries exceeded",
            api_name=self.api_name,
            status_code=500
        )

    def request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Make API request with error handling.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            data: Request body
            params: Query parameters
            **kwargs: Additional arguments for requests
            
        Returns:
            Response JSON as dictionary
            
        Raises:
            APIError: If request fails
            RateLimitExceededError: If rate limited
            APITimeoutError: If request times out
        """
        # Check rate limit
        get_rate_limiter(self.api_name).wait_if_needed(self.api_name)
        
        # Build URL
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        # Merge defaults with provided kwargs
        request_kwargs = {
            'timeout': self.timeout,
            'verify': True,  # Always verify SSL
        }
        request_kwargs.update(kwargs)
        
        start_time = time.time()
        
        try:
            with PerformanceLogger(f"{self.api_name}_request", endpoint):
                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    json=data,
                    params=params,
                    **request_kwargs
                )
                
                duration = time.time() - start_time
                
                # Log API call
                audit_logger.log_api_call(
                    self.api_name,
                    endpoint,
                    response.status_code,
                    duration
                )
                
                # Check for errors
                if response.status_code >= 400:
                    self._handle_response_error(response)
                
                # Parse response
                try:
                    return response.json()
                except ValueError:
                    raise APIError(
                        message="Invalid JSON response",
                        api_name=self.api_name,
                        status_code=500
                    )
        
        except requests.Timeout as e:
            duration = time.time() - start_time
            logger.error(f"{self.api_name} request timeout after {duration:.2f}s")
            audit_logger.log_api_call(
                self.api_name,
                endpoint,
                None,
                duration,
                f"Timeout after {duration:.2f}s"
            )
            raise APITimeoutError(self.api_name, self.timeout[1])
        
        except requests.ConnectionError as e:
            duration = time.time() - start_time
            logger.error(f"{self.api_name} connection error: {e}")
            audit_logger.log_api_call(
                self.api_name,
                endpoint,
                None,
                duration,
                f"Connection error: {str(e)}"
            )
            raise APIConnectionError(self.api_name, str(e))

    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scan URL using threat intelligence API.
        
        Args:
            url: URL to scan
            
        Returns:
            Scan results
        """
        # Try cache first
        cache_key = f"{self.api_name}:scan:{url}"
        cached_result = api_cache.get(cache_key)
        if cached_result:
            logger.info(f"URL scan cache hit: {url}")
            return cached_result
        
        # Perform scan
        result = self._perform_scan(url)
        
        # Cache result
        api_cache.set(cache_key, result)
        
        return result

    def _perform_scan(self, url: str) -> Dict[str, Any]:
        """
        Implementation of URL scan.
        
        Args:
            url: URL to scan
            
        Returns:
            Scan results
        """
        # API-specific scan implementations
        if self.api_name.lower() == 'a2a':
            return self._scan_a2a(url)
        elif self.api_name.lower() == 'plexiglass':
            return self._scan_plexiglass(url)
        else:
            raise NotImplementedError(f"Scan not implemented for {self.api_name}")

    def _scan_a2a(self, url: str) -> Dict[str, Any]:
        """
        Scan URL using A2A API.
        
        Args:
            url: URL to scan
            
        Returns:
            A2A scan results
        """
        dev_mode = "?development_mode=true" if Config.A2A_DEV_MODE else ""
        
        response = self.request(
            'POST',
            f'/urls/scan{dev_mode}',
            data={'url': url}
        )
        
        return response

    def _scan_plexiglass(self, url: str) -> Dict[str, Any]:
        """
        Scan URL using Plexiglass API.
        
        Args:
            url: URL to scan
            
        Returns:
            Plexiglass scan results
        """
        response = self.request(
            'POST',
            '/analyze',
            data={'url': url}
        )
        
        return response

    def get_health(self) -> bool:
        """
        Check API health/availability.
        
        Returns:
            True if API is available, False otherwise
        """
        try:
            response = self.request('GET', '/health')
            return response.get('status') == 'ok'
        except:
            return False

    def close(self) -> None:
        """Close session and release resources."""
        self.session.close()
        logger.info(f"Closed {self.api_name} API client")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class APIClientFactory:
    """
    Factory for creating API clients with proper configuration.
    
    Manages API client instances and ensures proper initialization.
    """

    _clients: Dict[str, ThreatIntelligenceAPIClient] = {}

    @classmethod
    def get_client(cls, api_name: str) -> Optional[ThreatIntelligenceAPIClient]:
        """
        Get or create API client.
        
        Args:
            api_name: Name of API service
            
        Returns:
            API client instance or None if not configured
        """
        if api_name in cls._clients:
            return cls._clients[api_name]
        
        # Get API key from configuration
        api_keys = Config.get_api_keys()
        api_key = api_keys.get(api_name.lower())
        
        if not api_key:
            logger.warning(f"No API key configured for {api_name}")
            return None
        
        try:
            client = ThreatIntelligenceAPIClient(api_name, api_key)
            cls._clients[api_name] = client
            return client
        except Exception as e:
            logger.error(f"Failed to create {api_name} client: {e}")
            return None

    @classmethod
    def get_enabled_clients(cls) -> Dict[str, ThreatIntelligenceAPIClient]:
        """
        Get all enabled API clients.
        
        Returns:
            Dictionary of enabled clients
        """
        enabled_services = Config.get_enabled_services()
        clients = {}
        
        for service_name, enabled in enabled_services.items():
            if enabled and not service_name.startswith('_'):
                client = cls.get_client(service_name)
                if client:
                    clients[service_name] = client
        
        return clients

    @classmethod
    def close_all(cls) -> None:
        """Close all API client connections."""
        for client in cls._clients.values():
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Error closing client: {e}")
        
        cls._clients.clear()
