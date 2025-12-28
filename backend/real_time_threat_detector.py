"""
REAL-TIME THREAT DETECTOR
Integrated threat detection using multiple threat intelligence APIs
- VirusTotal v3 API
- Google Safe Browsing API v4
- IPQualityScore API
"""

import requests
import time
import hashlib
from urllib.parse import urlparse, quote
from datetime import datetime, timedelta
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# API Configuration
class ThreatDetectorConfig:
    """Configuration for threat detection APIs"""
    
    # API Keys (should be set from environment variables)
    VIRUSTOTAL_API_KEY = None
    GOOGLE_SAFE_BROWSING_API_KEY = None
    IPQUALITYSCORE_API_KEY = None
    
    # API Endpoints
    VIRUSTOTAL_URL_SUBMIT = "https://www.virustotal.com/api/v3/urls"
    VIRUSTOTAL_URL_ANALYSE = "https://www.virustotal.com/api/v3/urls/{url_id}"
    
    GOOGLE_SAFEBROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    IPQUALITYSCORE_URL = "https://api.abuseipdb.com/api/v2/check"
    IPQS_URL_API = "https://ipqualityscore.com/api/json/url/detect"
    
    # Timeouts and retries
    TIMEOUT = 10  # seconds
    MAX_RETRIES = 2
    RETRY_DELAY = 2  # seconds
    
    # Cache settings
    CACHE_TTL = 3600  # 1 hour in seconds


class RealTimeThreatDetector:
    """
    Real-time threat detector using multiple threat intelligence APIs
    """
    
    def __init__(self, config: ThreatDetectorConfig = None):
        """Initialize detector with API configuration"""
        self.config = config or ThreatDetectorConfig()
        self.session = requests.Session()
        self.results_cache = {}
        
        logger.info("🚀 Real-Time Threat Detector Initialized")
        logger.info(f"   VirusTotal: {'✓' if self.config.VIRUSTOTAL_API_KEY else '✗'}")
        logger.info(f"   Google Safe Browsing: {'✓' if self.config.GOOGLE_SAFE_BROWSING_API_KEY else '✗'}")
        logger.info(f"   IPQualityScore: {'✓' if self.config.IPQUALITYSCORE_API_KEY else '✗'}")
    
    def detect(self, url: str) -> Dict:
        """
        Detect threats for a given URL using multiple APIs in parallel
        
        Args:
            url: URL to scan
            
        Returns:
            dict: Detection result with confidence, risk level, and API details
        """
        
        # Validate URL
        if not self._is_valid_url(url):
            return self._error_response(url, "Invalid URL format")
        
        # ALWAYS check FRESH - don't use cache for real-time threat detection
        # Security requires current API data, not old cached results
        logger.info(f"🔍 Scanning URL: {url} (REAL-TIME - Fresh API Check)")
        
        # Check URL patterns first (malware test sites, known threats)
        pattern_detection = self._check_url_patterns(url)
        
        # Run all API checks in parallel
        results = self._run_parallel_checks(url)
        
        # Aggregate results with pattern detection
        detection_result = self._aggregate_results(url, results, pattern_detection)
        
        # Don't cache - always return fresh real-time results
        # Security requires current threat intelligence, not stale cached data
        return detection_result
    
    def _check_url_patterns(self, url: str) -> Dict:
        """
        Check URL for malware patterns and known test sites
        Analyzes full URL path, not just domain
        """
        logger.info(f"🔎 Checking URL patterns for: {url}")
        
        url_lower = url.lower()
        parsed = urlparse(url_lower)
        full_path = f"{parsed.netloc}{parsed.path}"
        
        # Known malware test site patterns
        malware_patterns = [
            'test-malware',
            'test-trojan',
            'test-virus',
            'test-exploit',
            'test-ransomware',
            'test-botnet',
            'malware.test',
            'trojan.test',
            'virus.test',
            'phishing.test',
            'wicar.org/test',
            'eicar.org',
            'eicar-test',
            'malware-test',
        ]
        
        # Suspicious keywords
        suspicious_keywords = [
            'malware',
            'trojan',
            'ransomware',
            'botnet',
            'virus',
            'exploit',
            'payload',
            'phishing',
            'keylogger',
            'spyware',
            'rootkit'
        ]
        
        findings = []
        malicious_pattern = False
        suspicious_pattern = False
        
        # Check for known malware test patterns
        for pattern in malware_patterns:
            if pattern in full_path:
                findings.append(f"Known malware test site pattern detected: {pattern}")
                malicious_pattern = True
                logger.warning(f"⚠️ MALWARE TEST PATTERN DETECTED: {pattern}")
                break
        
        # Check for suspicious keywords in full URL path
        if not malicious_pattern:
            for keyword in suspicious_keywords:
                if keyword in full_path:
                    findings.append(f"Suspicious keyword in URL: {keyword}")
                    suspicious_pattern = True
                    logger.warning(f"⚠️ SUSPICIOUS KEYWORD DETECTED: {keyword}")
                    break
        
        return {
            'malicious': malicious_pattern,
            'suspicious': suspicious_pattern,
            'findings': findings,
            'checked': True
        }
    
    def _run_parallel_checks(self, url: str) -> Dict:
        """Run all threat checks in parallel"""
        results = {
            'virustotal': None,
            'safebrowsing': None,
            'ipqualityscore': None
        }
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}
            
            # Submit all checks
            if self.config.VIRUSTOTAL_API_KEY:
                futures['virustotal'] = executor.submit(self._check_virustotal, url)
            
            if self.config.GOOGLE_SAFE_BROWSING_API_KEY:
                futures['safebrowsing'] = executor.submit(self._check_safebrowsing, url)
            
            if self.config.IPQUALITYSCORE_API_KEY:
                futures['ipqualityscore'] = executor.submit(self._check_ipqualityscore, url)
            
            # Collect results as they complete
            for api_name, future in futures.items():
                try:
                    results[api_name] = future.result(timeout=self.config.TIMEOUT)
                except Exception as e:
                    logger.error(f"❌ {api_name} check failed: {str(e)}")
                    results[api_name] = {'error': str(e), 'success': False}
        
        return results
    
    def _check_virustotal(self, url: str) -> Dict:
        """
        Check URL with VirusTotal API
        Returns results from 90+ antivirus engines
        """
        logger.info(f"📤 Checking VirusTotal for {url}")
        
        try:
            headers = {'x-apikey': self.config.VIRUSTOTAL_API_KEY}
            
            # Submit URL for scanning
            submit_response = requests.post(
                self.config.VIRUSTOTAL_URL_SUBMIT,
                headers=headers,
                data={'url': url},
                timeout=self.config.TIMEOUT
            )
            
            if submit_response.status_code != 200:
                return {
                    'success': False,
                    'error': f'Submission failed: {submit_response.status_code}'
                }
            
            # Extract analysis ID
            submission_data = submit_response.json()
            url_id = submission_data.get('data', {}).get('id')
            
            if not url_id:
                return {'success': False, 'error': 'No URL ID returned'}
            
            logger.info(f"   URL submitted with ID: {url_id}")
            
            # Wait a bit for analysis to complete
            time.sleep(3)
            
            # Get analysis results
            analysis_response = requests.get(
                self.config.VIRUSTOTAL_URL_ANALYSE.format(url_id=url_id),
                headers=headers,
                timeout=self.config.TIMEOUT
            )
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                last_analysis_stats = analysis_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                # Use last_analysis_stats if available
                if last_analysis_stats:
                    stats = last_analysis_stats
                
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)
                harmless_count = stats.get('harmless', 0)
                undetected_count = stats.get('undetected', 0)
                
                # Calculate confidence (0-100)
                total_engines = malicious_count + suspicious_count + harmless_count + undetected_count
                confidence = (malicious_count * 100 + suspicious_count * 50) / max(total_engines, 1)
                
                logger.info(f"   ✅ VirusTotal Result:")
                logger.info(f"      Malicious: {malicious_count}, Suspicious: {suspicious_count}")
                logger.info(f"      Harmless: {harmless_count}, Undetected: {undetected_count}")
                logger.info(f"      Confidence: {confidence:.1f}%")
                
                return {
                    'success': True,
                    'malicious': malicious_count,
                    'suspicious': suspicious_count,
                    'harmless': harmless_count,
                    'undetected': undetected_count,
                    'confidence': confidence,
                    'total_engines': total_engines,
                    'risk_score': confidence
                }
            else:
                logger.warning(f"   ⚠️ Analysis not ready yet (status: {analysis_response.status_code})")
                return {
                    'success': False,
                    'error': 'Analysis not ready',
                    'status_code': analysis_response.status_code
                }
        
        except requests.Timeout:
            logger.error(f"❌ VirusTotal timeout")
            return {'success': False, 'error': 'Request timeout'}
        except Exception as e:
            logger.error(f"❌ VirusTotal error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _check_safebrowsing(self, url: str) -> Dict:
        """
        Check URL with Google Safe Browsing API
        Returns threats from Google's malware/phishing databases
        """
        logger.info(f"📤 Checking Google Safe Browsing for {url}")
        
        try:
            # Prepare request
            request_body = {
                'client': {
                    'clientId': 'cyber-guard-ai',
                    'clientVersion': '1.0.0'
                },
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            params = {'key': self.config.GOOGLE_SAFE_BROWSING_API_KEY}
            
            response = requests.post(
                self.config.GOOGLE_SAFEBROWSING_URL,
                json=request_body,
                params=params,
                timeout=self.config.TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                if matches:
                    threat_types = [match.get('threatType', 'UNKNOWN') for match in matches]
                    logger.info(f"   ⚠️ Google Safe Browsing THREAT detected: {threat_types}")
                    
                    return {
                        'success': True,
                        'malicious': True,
                        'threat_types': threat_types,
                        'confidence': 95,
                        'risk_score': 95
                    }
                else:
                    logger.info(f"   ✅ Google Safe Browsing: SAFE")
                    return {
                        'success': True,
                        'malicious': False,
                        'threat_types': [],
                        'confidence': 95,
                        'risk_score': 0
                    }
            else:
                logger.warning(f"   ⚠️ Google Safe Browsing error: {response.status_code}")
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}'
                }
        
        except requests.Timeout:
            logger.error(f"❌ Google Safe Browsing timeout")
            return {'success': False, 'error': 'Request timeout'}
        except Exception as e:
            logger.error(f"❌ Google Safe Browsing error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _check_ipqualityscore(self, url: str) -> Dict:
        """
        Check URL with IPQualityScore API
        Returns fraud/phishing risk assessment
        """
        logger.info(f"📤 Checking IPQualityScore for {url}")
        
        try:
            params = {
                'url': url,
                'key': self.config.IPQUALITYSCORE_API_KEY,
                'strictness': 0  # 0 = lenient, 1 = balanced, 2 = strict
            }
            
            response = requests.get(
                self.config.IPQS_URL_API,
                params=params,
                timeout=self.config.TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                fraud_score = data.get('fraud_score', 0)  # 0-100
                is_suspicious = data.get('suspicious', False)
                threat_types = data.get('threat_types', [])
                
                logger.info(f"   IPQualityScore Result:")
                logger.info(f"      Fraud Score: {fraud_score}/100")
                logger.info(f"      Suspicious: {is_suspicious}")
                logger.info(f"      Threats: {threat_types}")
                
                # Convert fraud score to risk score
                risk_score = fraud_score
                malicious = risk_score > 75
                
                return {
                    'success': True,
                    'fraud_score': fraud_score,
                    'malicious': malicious,
                    'suspicious': is_suspicious,
                    'threat_types': threat_types,
                    'confidence': 85,
                    'risk_score': risk_score
                }
            else:
                logger.warning(f"   ⚠️ IPQualityScore error: {response.status_code}")
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}'
                }
        
        except requests.Timeout:
            logger.error(f"❌ IPQualityScore timeout")
            return {'success': False, 'error': 'Request timeout'}
        except Exception as e:
            logger.error(f"❌ IPQualityScore error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _aggregate_results(self, url: str, api_results: Dict, pattern_detection: Dict = None) -> Dict:
        """
        Aggregate results from all APIs using weighted confidence
        """
        logger.info(f"📊 Aggregating results for {url}")
        
        if pattern_detection is None:
            pattern_detection = {'malicious': False, 'suspicious': False, 'findings': []}
        
        # LOG PATTERN DETECTION RESULTS
        logger.warning(f"🔎 PATTERN DETECTION RESULTS:")
        logger.warning(f"   Malicious: {pattern_detection.get('malicious')}")
        logger.warning(f"   Suspicious: {pattern_detection.get('suspicious')}")
        logger.warning(f"   Findings: {pattern_detection.get('findings')}")
        
        # LOG API RESULTS
        logger.warning(f"📡 API RESULTS:")
        for api_name, result in api_results.items():
            if result:
                logger.warning(f"   {api_name}: success={result.get('success')}, malicious={result.get('malicious')}")
        
        malicious_votes = 0
        safe_votes = 0
        suspicious_votes = 0
        total_success = 0
        confidence_scores = []
        all_findings = []
        
        # Check URL patterns FIRST (highest priority)
        if pattern_detection.get('malicious'):
            malicious_votes += 2
            all_findings.append(f"🚨 Malware test site pattern detected!")
            logger.warning("🚨 MALWARE TEST SITE PATTERN DETECTED - MARKING AS MALICIOUS")
        elif pattern_detection.get('suspicious'):
            suspicious_votes += 1
            all_findings.append(f"⚠️ Suspicious keyword in URL detected")
            logger.warning("⚠️ SUSPICIOUS KEYWORD IN URL")
        
        # VirusTotal (weight: 0.4 - 90+ engines)
        vt = api_results.get('virustotal', {})
        if vt.get('success'):
            total_success += 1
            vt_malicious = vt.get('malicious', 0)
            if vt_malicious >= 5:
                malicious_votes += 2
                all_findings.append(f"VirusTotal: {vt_malicious} antivirus engines detected threats")
            elif vt_malicious > 0:
                suspicious_votes += 1
                all_findings.append(f"VirusTotal: {vt_malicious} antivirus engine(s) flagged")
            else:
                safe_votes += 1
            confidence_scores.append(('virustotal', vt.get('risk_score', 0), 0.4))
        
        # Google Safe Browsing (weight: 0.35 - official Google database)
        gsb = api_results.get('safebrowsing', {})
        if gsb.get('success'):
            total_success += 1
            if gsb.get('malicious'):
                malicious_votes += 2
                threat_types = gsb.get('threat_types', [])
                all_findings.append(f"Google Safe Browsing: {', '.join(threat_types)}")
            else:
                safe_votes += 1
            confidence_scores.append(('safebrowsing', gsb.get('risk_score', 0), 0.35))
        
        # IPQualityScore (weight: 0.25 - fraud/phishing detection)
        ipqs = api_results.get('ipqualityscore', {})
        if ipqs.get('success'):
            total_success += 1
            fraud_score = ipqs.get('fraud_score', 0)
            if fraud_score > 75:
                malicious_votes += 1
                all_findings.append(f"IPQualityScore: High fraud risk ({fraud_score}/100)")
            elif fraud_score > 50:
                suspicious_votes += 1
                all_findings.append(f"IPQualityScore: Moderate fraud risk ({fraud_score}/100)")
            else:
                safe_votes += 1
            confidence_scores.append(('ipqualityscore', fraud_score, 0.25))
        
        # Calculate weighted confidence
        weighted_risk = 0
        total_weight = 0
        for api_name, score, weight in confidence_scores:
            weighted_risk += score * weight
            total_weight += weight
        
        if total_weight > 0:
            weighted_risk = weighted_risk / total_weight
        
        # LOG VOTING RESULTS
        logger.warning(f"🗳️  VOTING RESULTS:")
        logger.warning(f"   Malicious votes: {malicious_votes}")
        logger.warning(f"   Suspicious votes: {suspicious_votes}")
        logger.warning(f"   Safe votes: {safe_votes}")
        logger.warning(f"   Weighted risk: {weighted_risk:.1f}%")
        
        # Determine threat level - LOWERED THRESHOLDS FOR BETTER DETECTION
        if malicious_votes >= 2 or weighted_risk > 70 or (pattern_detection.get('malicious') and malicious_votes >= 1):
            threat_level = 'MALICIOUS'
            classification = '🔴 MALICIOUS'
        elif malicious_votes >= 1 or suspicious_votes > 0 or weighted_risk > 40 or pattern_detection.get('suspicious'):
            threat_level = 'SUSPICIOUS'
            classification = '⚠️ SUSPICIOUS'
        else:
            threat_level = 'SAFE'
            classification = '✅ SAFE'
        
        # LOG FINAL DECISION
        logger.warning(f"⚖️  FINAL DECISION:")
        logger.warning(f"   Threat Level: {threat_level}")
        logger.warning(f"   Classification: {classification}")
        
        # Build response
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'threat_level': threat_level,
            'classification': classification,
            'overall_risk_score': round(weighted_risk, 1),
            'confidence': round((total_success / 3) * 100, 1) if total_success > 0 else 0,
            'votes': {
                'malicious': malicious_votes,
                'suspicious': suspicious_votes,
                'safe': safe_votes,
                'total_apis': total_success
            },
            'findings': all_findings,
            'api_results': {
                'virustotal': vt if vt.get('success') else None,
                'safebrowsing': gsb if gsb.get('success') else None,
                'ipqualityscore': ipqs if ipqs.get('success') else None
            },
            'scan_duration': datetime.now().isoformat()
        }
        
        logger.info(f"🎯 Final Verdict: {classification} (Risk: {result['overall_risk_score']}%)")
        
        return result
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _get_cached_result(self, url: str) -> Optional[Dict]:
        """Get cached result if still valid"""
        if url in self.results_cache:
            result, timestamp = self.results_cache[url]
            if time.time() - timestamp < self.config.CACHE_TTL:
                return result
            else:
                del self.results_cache[url]
        return None
    
    def _cache_result(self, url: str, result: Dict):
        """Cache detection result"""
        self.results_cache[url] = (result, time.time())
    
    def _error_response(self, url: str, error: str) -> Dict:
        """Generate error response"""
        return {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'error': error,
            'threat_level': 'UNKNOWN',
            'overall_risk_score': 0
        }


# Initialize global detector instance
def create_detector(virustotal_key: str = None, safebrowsing_key: str = None, ipqs_key: str = None) -> RealTimeThreatDetector:
    """
    Factory function to create threat detector with API keys
    
    Args:
        virustotal_key: VirusTotal API key
        safebrowsing_key: Google Safe Browsing API key
        ipqs_key: IPQualityScore API key
        
    Returns:
        RealTimeThreatDetector instance
    """
    config = ThreatDetectorConfig()
    config.VIRUSTOTAL_API_KEY = virustotal_key
    config.GOOGLE_SAFE_BROWSING_API_KEY = safebrowsing_key
    config.IPQUALITYSCORE_API_KEY = ipqs_key
    
    return RealTimeThreatDetector(config)


if __name__ == "__main__":
    # Example usage
    detector = create_detector(
        virustotal_key="YOUR_API_KEY",
        safebrowsing_key="YOUR_API_KEY",
        ipqs_key="YOUR_API_KEY"
    )
    
    # Test with a URL
    test_url = "https://example.com"
    result = detector.detect(test_url)
    print(json.dumps(result, indent=2))
