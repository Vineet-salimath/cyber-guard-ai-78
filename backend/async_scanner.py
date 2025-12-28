"""
Asynchronous URL Scanner Module

Implements concurrent scanning of multiple URLs with proper timeout management,
error handling, and progress tracking.

Features:
- Async scanning of multiple URLs (configurable concurrency)
- Per-URL timeout (5-10 seconds)
- Progress tracking and callbacks
- Graceful error handling
- Result aggregation

Author: Security Team
Version: 1.0.0
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable, Coroutine
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime

from url_validator import validate_url, URLValidator
from error_handler import URLValidationError
from config import Config
from logging_config import get_logger, PerformanceLogger, get_audit_logger

logger = get_logger(__name__)
audit_logger = get_audit_logger()


@dataclass
class ScanResult:
    """
    Represents a single URL scan result.
    
    Attributes:
        url: Original URL that was scanned
        sanitized_url: Sanitized/normalized URL
        verdict: Scan verdict (safe/suspicious/malicious)
        risk_score: Risk score from 0-100
        threat_types: List of detected threat types
        scan_duration_seconds: Time taken to scan
        timestamp: When scan was completed
        error: Error message if scan failed
        raw_results: Raw results from security layers
    """

    url: str
    sanitized_url: str
    verdict: str
    risk_score: float
    threat_types: List[str]
    scan_duration_seconds: float
    timestamp: datetime
    error: Optional[str] = None
    raw_results: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

    @property
    def is_error(self) -> bool:
        """Check if scan resulted in error."""
        return self.error is not None


@dataclass
class BatchScanProgress:
    """
    Tracks progress of batch URL scanning.
    
    Attributes:
        total_urls: Total number of URLs to scan
        completed_urls: Number of completed scans
        failed_urls: Number of failed scans
        successful_urls: Number of successful scans
        start_time: When batch scan started
        estimated_completion: Estimated completion time
    """

    total_urls: int
    completed_urls: int = 0
    failed_urls: int = 0
    successful_urls: int = 0
    start_time: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None

    @property
    def progress_percent(self) -> float:
        """Get progress as percentage."""
        if self.total_urls == 0:
            return 0.0
        return (self.completed_urls / self.total_urls) * 100

    @property
    def elapsed_seconds(self) -> float:
        """Get elapsed time in seconds."""
        if not self.start_time:
            return 0.0
        return (datetime.now() - self.start_time).total_seconds()

    def update(self, success: bool) -> None:
        """Update progress with scan result."""
        self.completed_urls += 1
        if success:
            self.successful_urls += 1
        else:
            self.failed_urls += 1
        
        # Update estimated completion
        if self.completed_urls > 0:
            avg_per_url = self.elapsed_seconds / self.completed_urls
            remaining = self.total_urls - self.completed_urls
            remaining_seconds = avg_per_url * remaining
            self.estimated_completion = datetime.now() + asyncio.timedelta(
                seconds=remaining_seconds
            )


class AsyncURLScanner:
    """
    Asynchronous URL scanner with concurrent scanning support.
    
    Scans multiple URLs concurrently with configurable limits:
    - Maximum concurrent scans: Config.MAX_CONCURRENT_SCANS
    - Per-URL timeout: Config.REQUEST_TIMEOUT (5-10 seconds)
    - Maximum URLs per request: Config.MAX_URLS_PER_REQUEST
    
    Provides:
    - Concurrent scanning with proper timeout management
    - Progress tracking and callbacks
    - Error handling and recovery
    - Result aggregation and reporting
    
    Thread-safe implementation using ThreadPoolExecutor.
    """

    def __init__(
        self,
        max_concurrent: int = Config.MAX_CONCURRENT_SCANS,
        timeout_per_url: int = Config.REQUEST_TIMEOUT,
        progress_callback: Optional[Callable[[BatchScanProgress], None]] = None
    ):
        """
        Initialize async scanner.
        
        Args:
            max_concurrent: Maximum concurrent scans
            timeout_per_url: Timeout per URL in seconds
            progress_callback: Optional callback for progress updates
        """
        self.max_concurrent = max_concurrent
        self.timeout_per_url = timeout_per_url
        self.progress_callback = progress_callback
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent)

    def _validate_and_normalize(self, url: str) -> Optional[str]:
        """
        Validate and normalize URL.
        
        Args:
            url: URL to validate
            
        Returns:
            Normalized URL or None if validation fails
        """
        try:
            sanitized, _ = validate_url(url)
            return sanitized
        except URLValidationError as e:
            logger.warning(f"URL validation failed: {e.message}")
            return None

    def _create_scan_error(
        self,
        original_url: str,
        error_message: str,
        duration: float
    ) -> ScanResult:
        """
        Create error result for failed scan.
        
        Args:
            original_url: Original URL
            error_message: Error message
            duration: Scan duration
            
        Returns:
            ScanResult with error
        """
        return ScanResult(
            url=original_url,
            sanitized_url=original_url,
            verdict='error',
            risk_score=0.0,
            threat_types=[],
            scan_duration_seconds=duration,
            timestamp=datetime.now(),
            error=error_message,
            raw_results={}
        )

    async def scan_single_url(
        self,
        url: str,
        scan_function: Callable[[str], Dict[str, Any]]
    ) -> ScanResult:
        """
        Scan a single URL with timeout.
        
        Args:
            url: URL to scan
            scan_function: Function to perform actual scan
            
        Returns:
            ScanResult object
        """
        start_time = datetime.now()
        
        # Validate URL
        normalized_url = self._validate_and_normalize(url)
        if not normalized_url:
            duration = (datetime.now() - start_time).total_seconds()
            return self._create_scan_error(
                url,
                "URL validation failed",
                duration
            )
        
        try:
            # Run scan in thread pool with timeout
            loop = asyncio.get_event_loop()
            
            with PerformanceLogger("URL_Scan", normalized_url[:50]):
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        self.executor,
                        scan_function,
                        normalized_url
                    ),
                    timeout=self.timeout_per_url
                )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Create result from scan output
            return ScanResult(
                url=url,
                sanitized_url=normalized_url,
                verdict=result.get('verdict', 'unknown'),
                risk_score=result.get('risk_score', 0.0),
                threat_types=result.get('threat_types', []),
                scan_duration_seconds=duration,
                timestamp=datetime.now(),
                raw_results=result
            )
        
        except asyncio.TimeoutError:
            duration = (datetime.now() - start_time).total_seconds()
            logger.warning(f"URL scan timeout after {duration:.2f}s: {url}")
            
            audit_logger.log_security_event(
                'scan_timeout',
                'warning',
                f'URL scan timeout: {normalized_url}',
                {'url': normalized_url, 'timeout': self.timeout_per_url}
            )
            
            return self._create_scan_error(
                url,
                f"Scan timeout after {self.timeout_per_url} seconds",
                duration
            )
        
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"URL scan error: {e}")
            
            return self._create_scan_error(
                url,
                f"Scan failed: {str(e)}",
                duration
            )

    async def scan_batch(
        self,
        urls: List[str],
        scan_function: Callable[[str], Dict[str, Any]]
    ) -> List[ScanResult]:
        """
        Scan multiple URLs concurrently.
        
        Respects limits:
        - Maximum URLs per request
        - Maximum concurrent scans
        - Per-URL timeout
        
        Args:
            urls: List of URLs to scan
            scan_function: Function to perform actual scan
            
        Returns:
            List of ScanResult objects
        """
        # Validate input
        if not isinstance(urls, list):
            raise ValueError("URLs must be a list")
        
        if len(urls) > Config.MAX_URLS_PER_REQUEST:
            raise ValueError(
                f"Too many URLs. Maximum {Config.MAX_URLS_PER_REQUEST} allowed"
            )
        
        # Initialize progress tracking
        progress = BatchScanProgress(total_urls=len(urls))
        progress.start_time = datetime.now()
        
        # Create scan tasks with semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def bounded_scan(url: str) -> ScanResult:
            async with semaphore:
                result = await self.scan_single_url(url, scan_function)
                progress.update(success=not result.is_error)
                
                if self.progress_callback:
                    self.progress_callback(progress)
                
                return result
        
        # Run all scans concurrently
        tasks = [bounded_scan(url) for url in urls]
        
        logger.info(f"Starting batch scan of {len(urls)} URLs (max {self.max_concurrent} concurrent)")
        
        results = await asyncio.gather(*tasks)
        
        # Log summary
        logger.info(
            f"Batch scan complete: {progress.successful_urls} successful, "
            f"{progress.failed_urls} failed, elapsed {progress.elapsed_seconds:.2f}s"
        )
        
        audit_logger.log_scan(
            f"batch_{len(urls)}_urls",
            None,
            'completed',
            sum(r.risk_score for r in results) / len(results) if results else 0,
            progress.elapsed_seconds
        )
        
        return results

    def scan_urls_sync(
        self,
        urls: List[str],
        scan_function: Callable[[str], Dict[str, Any]]
    ) -> List[ScanResult]:
        """
        Synchronous wrapper for async batch scanning.
        
        Args:
            urls: List of URLs to scan
            scan_function: Function to perform actual scan
            
        Returns:
            List of ScanResult objects
        """
        # Create new event loop if needed
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        # Run async scan
        if loop.is_running():
            # Already in async context, use executor
            return loop.run_until_complete(
                self.scan_batch(urls, scan_function)
            )
        else:
            return loop.run_until_complete(
                self.scan_batch(urls, scan_function)
            )

    def close(self) -> None:
        """Close thread pool executor."""
        self.executor.shutdown(wait=True)
        logger.info("AsyncURLScanner closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


def create_scanner(
    max_concurrent: int = Config.MAX_CONCURRENT_SCANS,
    timeout_per_url: int = Config.REQUEST_TIMEOUT
) -> AsyncURLScanner:
    """
    Create async scanner instance.
    
    Args:
        max_concurrent: Maximum concurrent scans
        timeout_per_url: Timeout per URL
        
    Returns:
        AsyncURLScanner instance
    """
    return AsyncURLScanner(
        max_concurrent=max_concurrent,
        timeout_per_url=timeout_per_url
    )
