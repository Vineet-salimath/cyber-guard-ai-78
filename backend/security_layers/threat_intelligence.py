"""
LAYER C: THREAT INTELLIGENCE
Integration with multiple threat intelligence APIs and databases
"""

import requests
import hashlib
import time
from typing import Dict, List
from datetime import datetime, timedelta

class ThreatIntelligence:
    """Integrates multiple threat intelligence sources"""
    
    def __init__(self, api_keys: dict = None):
        """
        Initialize TI with API keys
        
        Args:
            api_keys: dict with keys for:
                - virustotal
                - abuseipdb
                - alienvault_otx (optional)
                - urlscan (optional)
        """
        self.api_keys = api_keys or {}
        self.cache = {}
        self.cache_duration = 3600  # 1 hour
        self.findings = []
        self.reputation_score = 100  # Start at 100 (clean), decrease for threats
    
    def analyze(self, url: str, domain: str = None) -> dict:
        """
        Check URL/domain against multiple TI sources
        
        Args:
            url: Full URL to check
            domain: Domain name (extracted if not provided)
        
        Returns:
            dict: TI results with reputation score and findings
        """
        self.findings = []
        self.reputation_score = 100
        
        try:
            from urllib.parse import urlparse
            if not domain:
                domain = urlparse(url).netloc
            
            # Extract IP if possible
            ip_address = self._resolve_domain_to_ip(domain)
            
            # Check all TI sources
            vt_result = self._check_virustotal(url)
            abuse_result = self._check_abuseipdb(ip_address) if ip_address else None
            otx_result = self._check_alienvault_otx(domain)
            phishtank_result = self._check_phishtank(url)
            openphish_result = self._check_openphish(url)
            urlscan_result = self._check_urlscan(url)
            
            # Aggregate results
            ti_sources = {
                'virustotal': vt_result,
                'abuseipdb': abuse_result,
                'alienvault_otx': otx_result,
                'phishtank': phishtank_result,
                'openphish': openphish_result,
                'urlscan': urlscan_result
            }
            
            # Calculate overall reputation
            self._calculate_reputation(ti_sources)
            
            return {
                'reputation_score': round(self.reputation_score, 2),
                'findings': self.findings,
                'sources': ti_sources,
                'status': 'completed',
                'checks_performed': len([s for s in ti_sources.values() if s])
            }
            
        except Exception as e:
            return {
                'reputation_score': 50,  # Neutral
                'findings': [f"TI analysis error: {str(e)}"],
                'sources': {},
                'status': 'error'
            }
    
    def _check_virustotal(self, url: str) -> dict:
        """Check URL against VirusTotal"""
        api_key = self.api_keys.get('virustotal')
        if not api_key or api_key == 'your_api_key_here':
            return {'status': 'no_api_key', 'threat_detected': False}
        
        try:
            # Check cache
            cache_key = f"vt_{hashlib.md5(url.encode()).hexdigest()}"
            if cache_key in self.cache:
                cached, timestamp = self.cache[cache_key]
                if time.time() - timestamp < self.cache_duration:
                    return cached
            
            # URL ID for VT API
            url_id = hashlib.sha256(url.encode()).hexdigest()
            
            headers = {'x-apikey': api_key}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                result = {
                    'status': 'success',
                    'threat_detected': malicious > 0 or suspicious > 3,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'total_engines': sum(stats.values())
                }
                
                if malicious > 0:
                    self.findings.append(f"🚨 VirusTotal: {malicious} engines detected as malicious")
                    self.reputation_score -= min(40, malicious * 5)
                elif suspicious > 3:
                    self.findings.append(f"⚠️ VirusTotal: {suspicious} engines marked suspicious")
                    self.reputation_score -= min(20, suspicious * 3)
                
                # Cache result
                self.cache[cache_key] = (result, time.time())
                return result
            
            return {'status': 'api_error', 'threat_detected': False}
            
        except Exception as e:
            return {'status': f'error: {str(e)}', 'threat_detected': False}
    
    def _check_abuseipdb(self, ip_address: str) -> dict:
        """Check IP against AbuseIPDB"""
        if not ip_address:
            return {'status': 'no_ip', 'threat_detected': False}
        
        api_key = self.api_keys.get('abuseipdb')
        if not api_key:
            return {'status': 'no_api_key', 'threat_detected': False}
        
        try:
            headers = {'Key': api_key, 'Accept': 'application/json'}
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params={'ipAddress': ip_address, 'maxAgeInDays': 90},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                abuse_score = data.get('abuseConfidenceScore', 0)
                is_public = data.get('isPublic', True)
                
                result = {
                    'status': 'success',
                    'threat_detected': abuse_score > 25,
                    'abuse_score': abuse_score,
                    'is_public': is_public,
                    'total_reports': data.get('totalReports', 0)
                }
                
                if abuse_score > 75:
                    self.findings.append(f"🚨 AbuseIPDB: High abuse score ({abuse_score}%)")
                    self.reputation_score -= 30
                elif abuse_score > 25:
                    self.findings.append(f"⚠️ AbuseIPDB: Moderate abuse score ({abuse_score}%)")
                    self.reputation_score -= 15
                
                return result
            
            return {'status': 'api_error', 'threat_detected': False}
            
        except Exception as e:
            return {'status': f'error: {str(e)}', 'threat_detected': False}
    
    def _check_alienvault_otx(self, domain: str) -> dict:
        """Check domain against AlienVault OTX"""
        api_key = self.api_keys.get('alienvault_otx')
        
        # OTX has a free tier without API key for basic queries
        try:
            response = requests.get(
                f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                
                result = {
                    'status': 'success',
                    'threat_detected': pulse_count > 0,
                    'pulse_count': pulse_count
                }
                
                if pulse_count > 5:
                    self.findings.append(f"🚨 AlienVault OTX: {pulse_count} threat pulses found")
                    self.reputation_score -= 25
                elif pulse_count > 0:
                    self.findings.append(f"⚠️ AlienVault OTX: {pulse_count} threat pulses")
                    self.reputation_score -= 10
                
                return result
            
            return {'status': 'api_error', 'threat_detected': False}
            
        except Exception as e:
            return {'status': f'error: {str(e)}', 'threat_detected': False}
    
    def _check_phishtank(self, url: str) -> dict:
        """Check URL against PhishTank database"""
        try:
            # PhishTank free API (limited)
            response = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data={
                    'url': url,
                    'format': 'json'
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                in_database = data.get('results', {}).get('in_database', False)
                is_phish = data.get('results', {}).get('valid', False)
                
                result = {
                    'status': 'success',
                    'threat_detected': is_phish,
                    'in_database': in_database
                }
                
                if is_phish:
                    self.findings.append("🚨 PhishTank: URL confirmed as phishing")
                    self.reputation_score -= 40
                
                return result
            
            return {'status': 'api_error', 'threat_detected': False}
            
        except Exception as e:
            return {'status': f'error: {str(e)}', 'threat_detected': False}
    
    def _check_openphish(self, url: str) -> dict:
        """Check URL against OpenPhish feed"""
        try:
            # Check if URL is in OpenPhish feed (simple check)
            # Note: Real implementation would download and cache the feed
            
            # Placeholder - would need to download feed from:
            # https://openphish.com/feed.txt
            
            return {
                'status': 'not_implemented',
                'threat_detected': False,
                'note': 'OpenPhish feed check requires downloading daily feed'
            }
            
        except Exception as e:
            return {'status': f'error: {str(e)}', 'threat_detected': False}
    
    def _check_urlscan(self, url: str) -> dict:
        """Check URL against urlscan.io"""
        api_key = self.api_keys.get('urlscan')
        
        try:
            # Search for existing scans
            response = requests.get(
                'https://urlscan.io/api/v1/search/',
                params={'q': f'page.url:"{url}"'},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                
                if results:
                    latest = results[0]
                    verdict = latest.get('verdicts', {}).get('overall', {})
                    is_malicious = verdict.get('malicious', False)
                    score = verdict.get('score', 0)
                    
                    result = {
                        'status': 'success',
                        'threat_detected': is_malicious,
                        'score': score,
                        'scans_found': len(results)
                    }
                    
                    if is_malicious:
                        self.findings.append(f"🚨 URLScan.io: Marked as malicious (score: {score})")
                        self.reputation_score -= 30
                    
                    return result
                
                return {'status': 'no_data', 'threat_detected': False}
            
            return {'status': 'api_error', 'threat_detected': False}
            
        except Exception as e:
            return {'status': f'error: {str(e)}', 'threat_detected': False}
    
    def _resolve_domain_to_ip(self, domain: str) -> str:
        """Resolve domain to IP address"""
        try:
            import socket
            ip = socket.gethostbyname(domain)
            return ip
        except:
            return None
    
    def _calculate_reputation(self, sources: dict):
        """Calculate overall reputation from all sources"""
        threat_count = sum(
            1 for source in sources.values() 
            if source and source.get('threat_detected')
        )
        
        if threat_count == 0:
            self.findings.append("✅ No threats found in threat intelligence databases")
        elif threat_count == 1:
            self.findings.append(f"⚠️ 1 threat intelligence source flagged this URL")
        else:
            self.findings.append(f"🚨 {threat_count} threat intelligence sources flagged this URL")
        
        # Ensure reputation score stays in valid range
        self.reputation_score = max(0, min(100, self.reputation_score))


# Quick test
if __name__ == "__main__":
    # Test with no API keys
    ti = ThreatIntelligence()
    result = ti.analyze("https://example.com")
    
    print(f"Reputation Score: {result['reputation_score']}/100")
    print(f"Findings:")
    for finding in result['findings']:
        print(f"  {finding}")
