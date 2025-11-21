"""
LAYER D: SIGNATURE & YARA MATCHING
Pattern-based detection using regex signatures and YARA-like rules
"""

import re
from typing import List, Dict

class SignatureMatcher:
    """
    Pattern-based malware detection using signatures
    Similar to YARA but using Python regex for lightweight implementation
    """
    
    def __init__(self):
        self.findings = []
        self.signature_score = 0.0
        self.matches = []
        
        # Malware family signatures
        self.malware_signatures = self._load_malware_signatures()
        
        # Phishing signatures
        self.phishing_signatures = self._load_phishing_signatures()
        
        # Cryptomining signatures
        self.cryptomining_signatures = self._load_cryptomining_signatures()
        
        # Exploit kit signatures
        self.exploit_signatures = self._load_exploit_signatures()
    
    def analyze(self, url: str, page_data: dict = None) -> dict:
        """
        Run signature matching against URL and page content
        
        Args:
            url: URL to analyze
            page_data: Page content (HTML, scripts, etc.)
        
        Returns:
            dict: Signature matches and risk score
        """
        self.findings = []
        self.signature_score = 0.0
        self.matches = []
        
        try:
            # Match URL patterns
            self._match_url_signatures(url)
            
            if page_data:
                html = page_data.get('html', '')
                scripts = page_data.get('scripts', [])
                
                # Match HTML patterns
                self._match_html_signatures(html)
                
                # Match JavaScript patterns
                for script in scripts:
                    content = script.get('content', '')
                    self._match_js_signatures(content)
            
            # Normalize score
            self.signature_score = min(100, max(0, self.signature_score))
            
            return {
                'signature_score': round(self.signature_score, 2),
                'findings': self.findings,
                'matches': self.matches,
                'status': 'completed',
                'signatures_checked': self._count_signatures()
            }
            
        except Exception as e:
            return {
                'signature_score': 0,
                'findings': [f"Signature analysis error: {str(e)}"],
                'matches': [],
                'status': 'error'
            }
    
    def _load_malware_signatures(self) -> List[Dict]:
        """Load known malware JavaScript signatures"""
        return [
            {
                'name': 'Generic JavaScript Obfuscation',
                'pattern': r'eval\s*\(\s*unescape\s*\(',
                'severity': 'high',
                'score': 20
            },
            {
                'name': 'Base64 + eval Pattern',
                'pattern': r'eval\s*\(\s*atob\s*\(',
                'severity': 'high',
                'score': 20
            },
            {
                'name': 'String.fromCharCode Obfuscation',
                'pattern': r'String\.fromCharCode\s*\([^)]{50,}',
                'severity': 'medium',
                'score': 15
            },
            {
                'name': 'Excessive Function() Constructor',
                'pattern': r'Function\s*\(\s*["\']',
                'severity': 'medium',
                'score': 12
            },
            {
                'name': 'Hidden iframe Creation',
                'pattern': r'createElement\s*\(\s*["\']iframe["\'].*display\s*:\s*["\']none',
                'severity': 'high',
                'score': 18
            },
            {
                'name': 'Document.write() with eval',
                'pattern': r'document\.write\s*\([^)]*eval',
                'severity': 'high',
                'score': 20
            }
        ]
    
    def _load_phishing_signatures(self) -> List[Dict]:
        """Load phishing detection signatures"""
        return [
            {
                'name': 'Fake Login Form',
                'pattern': r'<form[^>]*>.*<input[^>]*type=["\']password["\'].*<input[^>]*name=["\']email',
                'severity': 'high',
                'score': 25
            },
            {
                'name': 'Credential Harvesting',
                'pattern': r'(username|email|password).*action=["\']https?://(?!.*(?:google|facebook|amazon|microsoft))',
                'severity': 'high',
                'score': 20
            },
            {
                'name': 'Fake Security Warning',
                'pattern': r'(account.*suspended|verify.*identity|unusual.*activity|confirm.*information)',
                'severity': 'medium',
                'score': 15
            },
            {
                'name': 'Cloned Brand Login',
                'pattern': r'<title>.*(PayPal|Apple|Microsoft|Google|Amazon).*Login.*</title>',
                'severity': 'high',
                'score': 22
            },
            {
                'name': 'Fake Security Badge',
                'pattern': r'<img[^>]*(secure|verified|trusted|ssl|certificate)[^>]*>',
                'severity': 'low',
                'score': 8
            }
        ]
    
    def _load_cryptomining_signatures(self) -> List[Dict]:
        """Load cryptomining detection signatures"""
        return [
            {
                'name': 'Coinhive Miner',
                'pattern': r'coinhive\.min\.js|CoinHive\.(User|Anonymous)',
                'severity': 'high',
                'score': 30
            },
            {
                'name': 'CryptoNight Miner',
                'pattern': r'cryptonight|cn/r|cn/half',
                'severity': 'high',
                'score': 28
            },
            {
                'name': 'WebAssembly Miner',
                'pattern': r'WebAssembly.*instantiate.*mining',
                'severity': 'high',
                'score': 25
            },
            {
                'name': 'Monero Mining',
                'pattern': r'(xmr|monero).*pool|stratum\+tcp',
                'severity': 'high',
                'score': 30
            },
            {
                'name': 'Mining Pool Connection',
                'pattern': r'wss?://.*\.(crypto-pool|mining|miner)\.',
                'severity': 'medium',
                'score': 20
            }
        ]
    
    def _load_exploit_signatures(self) -> List[Dict]:
        """Load exploit kit signatures"""
        return [
            {
                'name': 'RIG Exploit Kit',
                'pattern': r'/[a-z]{3,8}\?[a-z]=[0-9a-f]{32}',
                'severity': 'critical',
                'score': 35
            },
            {
                'name': 'Angler Exploit Kit',
                'pattern': r'\.swf.*AllowScriptAccess.*always',
                'severity': 'critical',
                'score': 35
            },
            {
                'name': 'Magnitude Exploit Kit',
                'pattern': r'[a-f0-9]{32}\.php\?[a-z]=[0-9]{10}',
                'severity': 'critical',
                'score': 35
            },
            {
                'name': 'Flash Exploit',
                'pattern': r'flash.*object.*data:application/x-shockwave',
                'severity': 'high',
                'score': 28
            }
        ]
    
    def _match_url_signatures(self, url: str):
        """Match URL against patterns"""
        url_lower = url.lower()
        
        # Check phishing patterns in URL
        phishing_url_patterns = [
            (r'https?://[^/]*paypal[^/]*\.(?!com)', 'Fake PayPal Domain', 25),
            (r'https?://[^/]*apple[^/]*\.(?!com)', 'Fake Apple Domain', 25),
            (r'https?://[^/]*amazon[^/]*\.(?!com)', 'Fake Amazon Domain', 25),
            (r'https?://[^/]*microsoft[^/]*\.(?!com)', 'Fake Microsoft Domain', 25),
            (r'https?://[^/]*google[^/]*\.(?!com)', 'Fake Google Domain', 25),
            (r'-login\.|secure-|verify-|account-', 'Suspicious Subdomain Pattern', 18),
            (r'\.(exe|scr|bat|cmd|vbs|ps1)$', 'Executable File Download', 30),
            (r'\.zip$.*password|\.rar$.*password', 'Password-Protected Archive', 15)
        ]
        
        for pattern, name, score in phishing_url_patterns:
            if re.search(pattern, url_lower, re.IGNORECASE):
                self.matches.append(name)
                self.findings.append(f"🚨 Signature match: {name}")
                self.signature_score += score
    
    def _match_html_signatures(self, html: str):
        """Match HTML content against signatures"""
        if not html:
            return
        
        for sig in self.phishing_signatures:
            if re.search(sig['pattern'], html, re.IGNORECASE | re.DOTALL):
                self.matches.append(sig['name'])
                self.findings.append(f"🚨 {sig['severity'].upper()}: {sig['name']}")
                self.signature_score += sig['score']
    
    def _match_js_signatures(self, js_content: str):
        """Match JavaScript content against signatures"""
        if not js_content:
            return
        
        # Check malware signatures
        for sig in self.malware_signatures:
            matches = re.findall(sig['pattern'], js_content, re.IGNORECASE | re.DOTALL)
            if matches:
                count = len(matches)
                self.matches.append(f"{sig['name']} (x{count})")
                self.findings.append(f"🚨 {sig['severity'].upper()}: {sig['name']} ({count} occurrences)")
                self.signature_score += sig['score'] * min(count, 3)  # Cap at 3x
        
        # Check cryptomining signatures
        for sig in self.cryptomining_signatures:
            if re.search(sig['pattern'], js_content, re.IGNORECASE):
                self.matches.append(sig['name'])
                self.findings.append(f"🚨 {sig['severity'].upper()}: {sig['name']} - Cryptominer detected")
                self.signature_score += sig['score']
        
        # Check exploit signatures
        for sig in self.exploit_signatures:
            if re.search(sig['pattern'], js_content, re.IGNORECASE):
                self.matches.append(sig['name'])
                self.findings.append(f"🚨 {sig['severity'].upper()}: {sig['name']} - Exploit detected")
                self.signature_score += sig['score']
    
    def _count_signatures(self) -> int:
        """Count total signatures available"""
        return (
            len(self.malware_signatures) +
            len(self.phishing_signatures) +
            len(self.cryptomining_signatures) +
            len(self.exploit_signatures)
        )


# IOC (Indicators of Compromise) Database
class IOCMatcher:
    """
    Match against known IOCs from GitHub repositories
    """
    
    def __init__(self):
        # These would be loaded from GitHub repos in production
        # e.g., abuse.ch, MISP, etc.
        self.malicious_domains = set()
        self.malicious_ips = set()
        self.malicious_hashes = set()
    
    def load_iocs_from_github(self):
        """
        Load IOCs from community sources
        
        Example sources:
        - https://github.com/mitchellkrogza/Phishing.Database
        - https://github.com/stamparm/maltrail
        - https://github.com/TheSpeedX/TBomb-WorldWide-SMS-Bomber
        """
        # Placeholder for GitHub IOC integration
        pass
    
    def check_domain(self, domain: str) -> bool:
        """Check if domain is in IOC list"""
        return domain.lower() in self.malicious_domains
    
    def check_ip(self, ip: str) -> bool:
        """Check if IP is in IOC list"""
        return ip in self.malicious_ips


# Quick test
if __name__ == "__main__":
    matcher = SignatureMatcher()
    
    # Test with malicious patterns
    test_data = {
        'html': '<form><input type="password" name="password"><input name="email"></form>',
        'scripts': [
            {'content': 'eval(atob("bWFsaWNpb3VzIGNvZGU="));'}
        ]
    }
    
    result = matcher.analyze("https://paypal-verify.tk/login", test_data)
    print(f"Signature Score: {result['signature_score']}/100")
    print(f"Matches: {len(result['matches'])}")
    for finding in result['findings']:
        print(f"  {finding}")
