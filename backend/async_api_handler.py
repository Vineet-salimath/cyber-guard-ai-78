"""
Async API Handler for MalwareSnipper
Handles concurrent API calls for Phase 2 (FAST) and Phase 3 (DEEP) scanning
"""

import asyncio
import aiohttp
import json
from typing import Dict, Any, Optional, List
import os
from dotenv import load_dotenv

load_dotenv()


class AsyncAPIHandler:
    """Handles concurrent API calls for threat intelligence and malware analysis"""
    
    def __init__(self, timeout=3000):
        """
        Initialize async API handler
        
        Args:
            timeout: Request timeout in milliseconds
        """
        self.timeout = timeout / 1000  # Convert to seconds
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.alienvault_key = os.getenv('ALIENVAULT_OTX_KEY')
    
    async def parallel_api_calls(self, url: str) -> Dict[str, Any]:
        """
        Execute all Phase 2 API calls simultaneously
        
        Args:
            url: URL to scan
        
        Returns:
            Dictionary with results from all APIs
        """
        async with aiohttp.ClientSession() as session:
            tasks = [
                self.check_virustotal_async(session, url),
                self.check_threat_intel_async(session, url),
                self.check_security_headers_async(session, url)
            ]
            
            # Wait for all with timeout
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            return {
                'virustotal': results[0] if not isinstance(results[0], Exception) else {'error': str(results[0])},
                'threat_intel': results[1] if not isinstance(results[1], Exception) else {'error': str(results[1])},
                'headers': results[2] if not isinstance(results[2], Exception) else {'error': str(results[2])}
            }
    
    async def check_virustotal_async(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """
        Check URL against VirusTotal API
        
        Args:
            session: aiohttp session
            url: URL to check
        
        Returns:
            VirusTotal results
        """
        try:
            if not self.virustotal_key:
                return {'available': False, 'reason': 'API key not configured'}
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {'x-apikey': self.virustotal_key}
            
            # Prepare URL for VirusTotal API
            async with session.post(
                'https://www.virustotal.com/api/v3/urls',
                data={'url': url},
                headers=headers,
                timeout=timeout,
                ssl=False
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    analysis_data = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return {
                        'successful': True,
                        'malicious': analysis_data.get('malicious', 0),
                        'suspicious': analysis_data.get('suspicious', 0),
                        'harmless': analysis_data.get('harmless', 0),
                        'undetected': analysis_data.get('undetected', 0)
                    }
                else:
                    return {'successful': False, 'status': response.status}
        
        except asyncio.TimeoutError:
            return {'successful': False, 'error': 'Timeout'}
        except Exception as e:
            return {'successful': False, 'error': str(e)}
    
    async def check_threat_intel_async(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """
        Check threat intelligence sources in parallel
        
        Args:
            session: aiohttp session
            url: URL to check
        
        Returns:
            Combined threat intelligence results
        """
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).hostname
            
            tasks = [
                self.check_abuseipdb_async(session, domain),
                self.check_alienvault_async(session, domain)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            return {
                'abuseipdb': results[0] if not isinstance(results[0], Exception) else {'error': str(results[0])},
                'alienvault': results[1] if not isinstance(results[1], Exception) else {'error': str(results[1])}
            }
        
        except Exception as e:
            return {'error': str(e)}
    
    async def check_abuseipdb_async(self, session: aiohttp.ClientSession, domain: str) -> Dict[str, Any]:
        """
        Check AbuseIPDB for domain reputation
        
        Args:
            session: aiohttp session
            domain: Domain to check
        
        Returns:
            AbuseIPDB results
        """
        try:
            if not self.abuseipdb_key:
                return {'available': False}
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {'Key': self.abuseipdb_key, 'Accept': 'application/json'}
            params = {
                'query': domain,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            async with session.get(
                'https://api.abuseipdb.com/api/v2/check',
                params=params,
                headers=headers,
                timeout=timeout,
                ssl=False
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    ip_data = data.get('data', {})
                    
                    return {
                        'successful': True,
                        'abuseConfidenceScore': ip_data.get('abuseConfidenceScore', 0),
                        'totalReports': ip_data.get('totalReports', 0),
                        'threatTypes': ip_data.get('threatTypes', [])
                    }
                else:
                    return {'successful': False, 'status': response.status}
        
        except asyncio.TimeoutError:
            return {'successful': False, 'error': 'Timeout'}
        except Exception as e:
            return {'successful': False, 'error': str(e)}
    
    async def check_alienvault_async(self, session: aiohttp.ClientSession, domain: str) -> Dict[str, Any]:
        """
        Check AlienVault OTX for threat pulses
        
        Args:
            session: aiohttp session
            domain: Domain to check
        
        Returns:
            AlienVault OTX results
        """
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with session.get(
                f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/pulses',
                timeout=timeout,
                ssl=False
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    pulses = data.get('results', [])
                    
                    return {
                        'successful': True,
                        'pulse_count': len(pulses),
                        'pulses': [
                            {
                                'name': pulse.get('name'),
                                'modified': pulse.get('modified'),
                                'adversary_ids': len(pulse.get('adversary_ids', []))
                            }
                            for pulse in pulses[:5]  # Top 5 pulses
                        ]
                    }
                else:
                    return {'successful': False, 'status': response.status}
        
        except asyncio.TimeoutError:
            return {'successful': False, 'error': 'Timeout'}
        except Exception as e:
            return {'successful': False, 'error': str(e)}
    
    async def check_security_headers_async(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        """
        Check HTTP security headers
        
        Args:
            session: aiohttp session
            url: URL to check
        
        Returns:
            Security headers analysis
        """
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            async with session.head(
                url,
                timeout=timeout,
                ssl=False,
                allow_redirects=True
            ) as response:
                headers = response.headers
                
                security_headers = {
                    'content-security-policy': headers.get('content-security-policy'),
                    'x-content-type-options': headers.get('x-content-type-options'),
                    'x-frame-options': headers.get('x-frame-options'),
                    'strict-transport-security': headers.get('strict-transport-security'),
                    'x-xss-protection': headers.get('x-xss-protection')
                }
                
                # Score the security headers
                score = sum(20 for v in security_headers.values() if v)
                
                return {
                    'successful': True,
                    'headers': {k: v for k, v in security_headers.items() if v},
                    'score': score,
                    'secure': score >= 60
                }
        
        except asyncio.TimeoutError:
            return {'successful': False, 'error': 'Timeout'}
        except Exception as e:
            return {'successful': False, 'error': str(e)}
    
    def run_parallel_scan(self, url: str) -> Dict[str, Any]:
        """
        Synchronous wrapper to run parallel async scan
        
        Args:
            url: URL to scan
        
        Returns:
            Results from all APIs
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results = loop.run_until_complete(self.parallel_api_calls(url))
            loop.close()
            
            return {
                'successful': True,
                'results': results
            }
        except Exception as e:
            return {
                'successful': False,
                'error': str(e)
            }


# Convenience function for integration
async def run_phase2_scan(url: str, timeout_ms: int = 3000) -> Dict[str, Any]:
    """
    Run Phase 2 (FAST) scan with parallel API calls
    
    Args:
        url: URL to scan
        timeout_ms: Timeout in milliseconds
    
    Returns:
        Phase 2 scan results
    """
    handler = AsyncAPIHandler(timeout=timeout_ms)
    return await handler.parallel_api_calls(url)
