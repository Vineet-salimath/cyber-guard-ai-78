"""
Performance Optimization Module

Implements caching for DNS/WHOIS lookups, connection pooling for HTTP requests,
and rate limiting for external APIs to prevent abuse and reduce latency.

Features:
- LRU cache for DNS/WHOIS lookups
- Connection pooling with configurable pool size
- Rate limiting with sliding window algorithm
- Cache statistics and monitoring
- TTL-based cache expiration

Author: Security Team
Version: 1.0.0
"""

import time
import logging
import threading
from typing import Dict, Any, Optional, Tuple, Callable, TypeVar
from collections import deque, defaultdict
from functools import wraps, lru_cache
from datetime import datetime, timedelta
import hashlib
import json

from config import Config
from error_handler import RateLimitExceededError, CacheError
from logging_config import PerformanceLogger

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CacheEntry:
    """
    Represents a single cache entry with TTL support.
    
    Stores value and expiration time for automatic invalidation.
    """

    def __init__(self, value: Any, ttl_seconds: int):
        """
        Initialize cache entry.
        
        Args:
            value: Value to cache
            ttl_seconds: Time-to-live in seconds
        """
        self.value = value
        self.created_at = time.time()
        self.ttl_seconds = ttl_seconds

    def is_expired(self) -> bool:
        """
        Check if cache entry has expired.
        
        Returns:
            True if entry has exceeded TTL, False otherwise
        """
        if self.ttl_seconds <= 0:
            return False
        
        return (time.time() - self.created_at) > self.ttl_seconds

    def get_value(self) -> Optional[Any]:
        """
        Get value if not expired.
        
        Returns:
            Value if valid, None if expired
        """
        if self.is_expired():
            return None
        return self.value


class TTLCache:
    """
    Thread-safe cache with TTL (Time-To-Live) support.
    
    Automatically expires entries after specified duration.
    Perfect for caching DNS lookups, WHOIS data, and API responses.
    
    Thread-safety achieved through threading.Lock.
    """

    def __init__(self, max_size: int = 1000, default_ttl_seconds: int = 3600):
        """
        Initialize TTL cache.
        
        Args:
            max_size: Maximum number of entries
            default_ttl_seconds: Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl_seconds
        self.cache: Dict[str, CacheEntry] = {}
        self.access_times: Dict[str, float] = {}
        self.lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def _cleanup_expired(self) -> None:
        """Remove expired entries from cache."""
        expired_keys = [
            key for key, entry in self.cache.items()
            if entry.is_expired()
        ]
        for key in expired_keys:
            del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """
        Set cache entry.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl_seconds: Optional TTL override
        """
        ttl = ttl_seconds or self.default_ttl
        
        with self.lock:
            # Remove expired entries if cache is full
            if len(self.cache) >= self.max_size:
                self._cleanup_expired()
            
            # If still full, remove least recently used
            if len(self.cache) >= self.max_size:
                lru_key = min(self.access_times, key=self.access_times.get)
                del self.cache[lru_key]
                del self.access_times[lru_key]
            
            # Add entry
            self.cache[key] = CacheEntry(value, ttl)
            self.access_times[key] = time.time()
            
            logger.debug(f"Cache SET: {key} (TTL: {ttl}s)")

    def get(self, key: str) -> Optional[Any]:
        """
        Get cache entry.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value if exists and not expired, None otherwise
        """
        with self.lock:
            if key not in self.cache:
                self.misses += 1
                return None
            
            entry = self.cache[key]
            value = entry.get_value()
            
            if value is None:
                # Entry expired
                del self.cache[key]
                if key in self.access_times:
                    del self.access_times[key]
                self.misses += 1
                return None
            
            # Update access time
            self.access_times[key] = time.time()
            self.hits += 1
            
            logger.debug(f"Cache HIT: {key}")
            return value

    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            logger.info("Cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with hit rate, size, and other metrics
        """
        with self.lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0
            
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate_percent': hit_rate,
            }


class RateLimiter:
    """
    Token bucket rate limiter with per-API and global limits.
    
    Uses sliding window algorithm to enforce rate limits.
    Supports both per-API limits and global limits.
    
    Thread-safe implementation using threading.Lock.
    """

    def __init__(
        self,
        requests_per_minute: int = Config.RATE_LIMIT_REQUESTS,
        window_seconds: int = Config.RATE_LIMIT_WINDOW
    ):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_minute: Requests allowed per time window
            window_seconds: Time window in seconds
        """
        self.requests_per_minute = requests_per_minute
        self.window_seconds = window_seconds
        
        # Request timestamps per API
        self.request_history: Dict[str, deque] = defaultdict(deque)
        
        # Lock for thread safety
        self.lock = threading.Lock()

    def _cleanup_old_requests(self, api_name: str, current_time: float) -> None:
        """Remove requests older than window from history."""
        cutoff_time = current_time - self.window_seconds
        history = self.request_history[api_name]
        
        while history and history[0] < cutoff_time:
            history.popleft()

    def is_allowed(self, api_name: str) -> bool:
        """
        Check if request is allowed under rate limit.
        
        Args:
            api_name: Name of API being called
            
        Returns:
            True if request is allowed, False if rate limited
        """
        current_time = time.time()
        
        with self.lock:
            # Clean up old requests
            self._cleanup_old_requests(api_name, current_time)
            
            history = self.request_history[api_name]
            
            # Check if under limit
            if len(history) < self.requests_per_minute:
                history.append(current_time)
                return True
            
            return False

    def wait_if_needed(self, api_name: str, timeout_seconds: float = 60.0) -> bool:
        """
        Wait until request is allowed or timeout.
        
        Args:
            api_name: Name of API
            timeout_seconds: Maximum time to wait
            
        Returns:
            True if allowed after waiting, False if timeout
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout_seconds:
            if self.is_allowed(api_name):
                return True
            time.sleep(0.1)  # Brief sleep before retry
        
        return False

    def get_retry_after(self, api_name: str) -> float:
        """
        Get seconds to wait before next request allowed.
        
        Args:
            api_name: Name of API
            
        Returns:
            Seconds to wait, or 0 if allowed now
        """
        current_time = time.time()
        
        with self.lock:
            self._cleanup_old_requests(api_name, current_time)
            history = self.request_history[api_name]
            
            if len(history) < self.requests_per_minute:
                return 0.0
            
            # Calculate wait time until oldest request falls out of window
            if history:
                oldest_request = history[0]
                wait_time = (oldest_request + self.window_seconds) - current_time
                return max(0.0, wait_time)
            
            return 0.0

    def get_stats(self, api_name: str) -> Dict[str, Any]:
        """
        Get rate limiter statistics for API.
        
        Args:
            api_name: Name of API
            
        Returns:
            Statistics dictionary
        """
        with self.lock:
            current_time = time.time()
            self._cleanup_old_requests(api_name, current_time)
            
            history = self.request_history[api_name]
            
            return {
                'api': api_name,
                'requests_in_window': len(history),
                'limit': self.requests_per_minute,
                'window_seconds': self.window_seconds,
                'available': self.requests_per_minute - len(history),
            }


class ConnectionPool:
    """
    Simple connection pool for HTTP requests.
    
    Maintains a pool of reusable connections to reduce overhead
    of creating new connections for each request.
    
    Integrates with requests library via HTTPAdapter.
    """

    def __init__(
        self,
        pool_size: int = Config.CONNECTION_POOL_SIZE,
        max_retries: int = 3,
        backoff_factor: float = 0.3
    ):
        """
        Initialize connection pool.
        
        Args:
            pool_size: Number of connections to maintain
            max_retries: Maximum retry attempts
            backoff_factor: Backoff factor for retries
        """
        self.pool_size = pool_size
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        
        logger.info(
            f"Connection pool initialized: "
            f"size={pool_size}, retries={max_retries}, backoff={backoff_factor}"
        )

    def get_session_config(self) -> Dict[str, Any]:
        """
        Get configuration for requests.Session.
        
        Returns:
            Dictionary with session configuration
        """
        return {
            'pool_connections': Config.POOL_CONNECTIONS,
            'pool_maxsize': Config.POOL_MAXSIZE,
            'max_retries': self.max_retries,
        }


class CachedFunction:
    """
    Decorator for caching function results with TTL.
    
    Usage:
        @CachedFunction(ttl_seconds=3600)
        def get_dns_info(domain: str) -> dict:
            return lookup_dns(domain)
    """

    def __init__(self, ttl_seconds: int = 3600, cache_size: int = 1000):
        """
        Initialize cached function decorator.
        
        Args:
            ttl_seconds: Cache TTL in seconds
            cache_size: Maximum cache entries
        """
        self.ttl_seconds = ttl_seconds
        self.cache = TTLCache(max_size=cache_size, default_ttl_seconds=ttl_seconds)

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """
        Decorator implementation.
        
        Args:
            func: Function to cache
            
        Returns:
            Wrapped function with caching
        """
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            # Create cache key from function name and arguments
            cache_key = self._make_cache_key(func.__name__, args, kwargs)
            
            # Try cache
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Returning cached result for {func.__name__}")
                return cached_result
            
            # Call function
            with PerformanceLogger(f"{func.__name__}_execution"):
                result = func(*args, **kwargs)
            
            # Cache result
            self.cache.set(cache_key, result, self.ttl_seconds)
            
            return result
        
        # Expose cache stats
        wrapper.cache_stats = self.cache.get_stats  # type: ignore
        wrapper.cache_clear = self.cache.clear  # type: ignore
        
        return wrapper

    @staticmethod
    def _make_cache_key(func_name: str, args: tuple, kwargs: dict) -> str:
        """
        Create cache key from function name and arguments.
        
        Args:
            func_name: Name of function
            args: Positional arguments
            kwargs: Keyword arguments
            
        Returns:
            Cache key string
        """
        # Convert args and kwargs to hashable form
        key_data = f"{func_name}:{args}:{sorted(kwargs.items())}"
        return hashlib.sha256(key_data.encode()).hexdigest()


# Global cache instances
dns_cache = TTLCache(max_size=1000, default_ttl_seconds=Config.DNS_CACHE_TTL)
whois_cache = TTLCache(max_size=500, default_ttl_seconds=Config.WHOIS_CACHE_TTL)
api_cache = TTLCache(max_size=5000, default_ttl_seconds=Config.CACHE_TTL_HOURS * 3600)

# Global rate limiters per API
rate_limiters: Dict[str, RateLimiter] = {
    'virustotal': RateLimiter(Config.VIRUSTOTAL_RATE_LIMIT),
    'urlscan': RateLimiter(Config.URLSCAN_RATE_LIMIT),
    'whois': RateLimiter(Config.WHOIS_RATE_LIMIT),
}


def get_rate_limiter(api_name: str) -> RateLimiter:
    """
    Get rate limiter for API.
    
    Creates new limiter if not exists.
    
    Args:
        api_name: Name of API
        
    Returns:
        Rate limiter instance
    """
    if api_name not in rate_limiters:
        rate_limiters[api_name] = RateLimiter(
            requests_per_minute=Config.RATE_LIMIT_REQUESTS
        )
    
    return rate_limiters[api_name]


def check_rate_limit(api_name: str) -> None:
    """
    Check if API request is allowed.
    
    Args:
        api_name: Name of API
        
    Raises:
        RateLimitExceededError: If rate limit exceeded
    """
    limiter = get_rate_limiter(api_name)
    
    if not limiter.is_allowed(api_name):
        retry_after = limiter.get_retry_after(api_name)
        logger.warning(f"Rate limit exceeded for {api_name}, retry after {retry_after:.1f}s")
        raise RateLimitExceededError(api_name, int(retry_after) + 1)


def get_cache_stats() -> Dict[str, Dict[str, Any]]:
    """
    Get statistics for all caches.
    
    Returns:
        Dictionary with stats for each cache
    """
    return {
        'dns_cache': dns_cache.get_stats(),
        'whois_cache': whois_cache.get_stats(),
        'api_cache': api_cache.get_stats(),
    }


def get_rate_limiter_stats(api_name: str) -> Dict[str, Any]:
    """
    Get rate limiter statistics.
    
    Args:
        api_name: Name of API
        
    Returns:
        Rate limiter statistics
    """
    limiter = get_rate_limiter(api_name)
    return limiter.get_stats(api_name)
