"""
LAYER A: STATIC ANALYSIS
Fast lexical and structural checks for URL and domain analysis
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter
import socket
from datetime import datetime

class StaticAnalyzer:
    """Performs fast static analysis on URLs without making network requests"""
    
    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', 
        '.click', '.link', '.download', '.zip', '.review', '.support',
        '.info', '.online', '.services', '.tech', '.site', '.website'
    }
    
    # Homoglyph characters (look-alike characters used in phishing)
    HOMOGLYPHS = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',  # Cyrillic
        '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't'  # Numbers
    }
    
    # CRITICAL PHISHING KEYWORDS (High-value indicators)
    CRITICAL_PHISHING_KEYWORDS = [
        'verify', 'confirm', 'validate', 'authenticate', 'authorize',
        'reset-password', 'update-password', 'change-password',
        'alert', 'warning', 'urgent', 'immediately', 'action-required',
        'suspended', 'locked', 'disabled', 'unusual-activity',
        'resolve', 'recover', 'secure', 'protection', 'security-check'
    ]
    
    # Suspicious keywords in URLs
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'account', 'verify', 'update', 'secure', 'confirm',
        'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
        'password', 'credential', 'auth', 'validate', 'suspended',
        'unusual', 'activity', 'locked', 'urgent', 'immediately',
        'click', 'prize', 'winner', 'free', 'gift', 'offer',
        'phishing', 'malicious', 'exploit', 'vulnerability', 'test',
        'alert', 'warning', 'check', 'session', 'reset', 'recover',
        'help', 'support', 'recovery', 'protection', 'authentication'
    ]
    
    # CRITICAL PHISHING INDICATORS
    PHISHING_DOMAINS = [
        'appspot.com', 'mcafee', 'testingmcafee', 'testsafe',
        'paypal', 'amazon', 'apple', 'microsoft', 'google'
    ]
    
    def __init__(self):
        self.findings = []
        self.risk_score = 0.0
    
    def analyze(self, url: str, page_data: dict = None) -> dict:
        """
        Perform comprehensive static analysis
        
        Args:
            url: URL to analyze
            page_data: Optional page content data (HTML, scripts, etc.)
        
        Returns:
            dict: Analysis results with findings and risk score
        """
        self.findings = []
        self.risk_score = 0.0
        
        try:
            parsed = urlparse(url)
            
            # Run all static checks
            self._check_url_length(url)
            self._check_entropy(url)
            self._check_special_characters(url)
            self._check_ip_address(parsed)
            self._check_suspicious_tld(parsed)
            self._check_homoglyphs(url)
            self._check_suspicious_keywords(url)
            self._check_subdomain_depth(parsed)
            self._check_suspicious_patterns(url)
            self._check_url_shortener(parsed)
            self._check_domain_impersonation(url)  # NEW CHECK
            self._check_hyphenated_keywords(url)  # NEW CHECK for multi-part domains
            
            # Analyze page data if provided
            if page_data:
                self._check_iframe_nesting(page_data)
                self._check_hidden_elements(page_data)
                self._check_suspicious_redirects(page_data)
            
            # Normalize risk score to 0-100
            self.risk_score = min(100, max(0, self.risk_score))
            
            return {
                'risk_score': round(self.risk_score, 2),
                'findings': self.findings,
                'status': 'completed',
                'checks_performed': 10 + (3 if page_data else 0)
            }
            
        except Exception as e:
            return {
                'risk_score': 0,
                'findings': [f"Analysis error: {str(e)}"],
                'status': 'error',
                'checks_performed': 0
            }
    
    def _check_url_length(self, url: str):
        """Check for abnormally long URLs (common in phishing)"""
        length = len(url)
        if length > 150:
            self.findings.append(f"Extremely long URL ({length} chars) - possible obfuscation")
            self.risk_score += 15
        elif length > 100:
            self.findings.append(f"Long URL ({length} chars) - slightly suspicious")
            self.risk_score += 8
    
    def _check_entropy(self, url: str):
        """Calculate Shannon entropy to detect randomness"""
        # Remove protocol and common patterns
        clean_url = re.sub(r'^https?://', '', url)
        
        if len(clean_url) < 10:
            return
        
        # Calculate entropy
        counter = Counter(clean_url)
        length = len(clean_url)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        
        # High entropy = random/obfuscated
        if entropy > 4.5:
            self.findings.append(f"High entropy ({entropy:.2f}) - possible random/obfuscated URL")
            self.risk_score += 12
        elif entropy > 4.0:
            self.findings.append(f"Elevated entropy ({entropy:.2f}) - slightly unusual")
            self.risk_score += 5
    
    def _check_special_characters(self, url: str):
        """Check for excessive special characters"""
        special_chars = re.findall(r'[@%$#&=?]', url)
        count = len(special_chars)
        
        if count > 10:
            self.findings.append(f"Excessive special characters ({count}) - suspicious")
            self.risk_score += 10
        elif count > 6:
            self.findings.append(f"Many special characters ({count})")
            self.risk_score += 5
        
        # Check for @ symbol (common phishing trick)
        if '@' in url:
            self.findings.append("Contains '@' symbol - potential credential phishing")
            self.risk_score += 20
    
    def _check_ip_address(self, parsed):
        """Check if domain is an IP address (suspicious)"""
        domain = parsed.netloc
        
        # IPv4 pattern
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$'
        if re.match(ipv4_pattern, domain):
            self.findings.append("URL uses IP address instead of domain - highly suspicious")
            self.risk_score += 25
            return
        
        # IPv6 pattern
        if '[' in domain and ']' in domain:
            self.findings.append("URL uses IPv6 address - suspicious")
            self.risk_score += 20
    
    def _check_suspicious_tld(self, parsed):
        """Check for suspicious top-level domains"""
        domain = parsed.netloc.lower()
        
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                self.findings.append(f"Suspicious TLD '{tld}' - commonly used in phishing")
                self.risk_score += 15
                break
        
        # Also check for suspicious domain patterns (verify/confirm + security keywords)
        if domain.startswith('verify-') or domain.startswith('confirm-') or '-verify-' in domain or '-confirm-' in domain:
            if any(keyword in domain for keyword in ['protect', 'security', 'check', 'validate', 'confirm', 'verify', 'alert', 'alert']):
                self.findings.append(f"Suspicious pattern: verify/confirm with protection/security keywords")
                self.risk_score += 25
    
    def _check_homoglyphs(self, url: str):
        """Detect homoglyph attacks (look-alike characters)"""
        url_lower = url.lower()
        detected_homoglyphs = []
        
        for homoglyph, normal in self.HOMOGLYPHS.items():
            if homoglyph in url_lower:
                detected_homoglyphs.append(f"'{homoglyph}' (looks like '{normal}')")
        
        if detected_homoglyphs:
            self.findings.append(f"Homoglyph characters detected: {', '.join(detected_homoglyphs)} - typosquatting attempt")
            self.risk_score += 20
    
    def _check_suspicious_keywords(self, url: str):
        """Check for phishing-related keywords with critical keyword boost"""
        url_lower = url.lower()
        found_keywords = []
        found_critical = []
        
        # Check for CRITICAL phishing keywords (very high confidence)
        for keyword in self.CRITICAL_PHISHING_KEYWORDS:
            if keyword in url_lower:
                found_critical.append(keyword)
        
        # Check for regular suspicious keywords
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                found_keywords.append(keyword)
        
        # Check for phishing-indicator domains
        for phishing_domain in self.PHISHING_DOMAINS:
            if phishing_domain.lower() in url_lower:
                self.findings.append(f"Phishing indicator domain detected: {phishing_domain}")
                self.risk_score += 35  # BOOST RISK FOR KNOWN PHISHING INDICATORS
        
        # CRITICAL KEYWORDS - Very high risk
        if found_critical:
            critical_count = len(found_critical)
            if critical_count >= 2:
                self.findings.append(f"CRITICAL: Multiple phishing keywords detected: {', '.join(found_critical[:3])}")
                self.risk_score += 40  # MASSIVE BOOST for 2+ critical indicators
            elif critical_count == 1:
                self.findings.append(f"CRITICAL: Phishing keyword detected: {found_critical[0]}")
                self.risk_score += 30  # LARGE BOOST for critical indicator
        
        # REGULAR KEYWORDS
        if found_keywords:
            count = len(found_keywords)
            if count >= 4:
                self.findings.append(f"Multiple suspicious keywords: {', '.join(found_keywords[:5])} - likely phishing")
                self.risk_score += 30  # INCREASED from 25
            elif count >= 3:
                self.findings.append(f"Multiple suspicious keywords: {', '.join(found_keywords[:3])}")
                self.risk_score += 25  # INCREASED from 25
            elif count >= 2:
                self.findings.append(f"Suspicious keywords: {', '.join(found_keywords)}")
                self.risk_score += 18  # INCREASED from 18
            elif count == 1:
                self.findings.append(f"Suspicious keyword: {found_keywords[0]}")
                self.risk_score += 8
    
    def _check_subdomain_depth(self, parsed):
        """Check for excessive subdomain nesting"""
        domain = parsed.netloc
        subdomain_count = domain.count('.') - 1  # -1 for main domain
        
        if subdomain_count >= 4:
            self.findings.append(f"Deep subdomain nesting ({subdomain_count} levels) - suspicious")
            self.risk_score += 12
        elif subdomain_count == 3:
            self.findings.append(f"Multiple subdomains ({subdomain_count} levels)")
            self.risk_score += 6
    
    def _check_suspicious_patterns(self, url: str):
        """Check for known suspicious patterns"""
        url_lower = url.lower()
        
        # Double extensions
        if re.search(r'\.(exe|zip|rar|scr|bat|cmd|vbs)\.(jpg|png|pdf|doc|txt)', url_lower):
            self.findings.append("Double extension detected - likely malware disguise")
            self.risk_score += 30
        
        # Data URIs
        if 'data:' in url_lower:
            self.findings.append("Data URI detected - possible embedded malicious content")
            self.risk_score += 15
        
        # Punycode (internationalized domain names)
        if 'xn--' in url_lower:
            self.findings.append("Punycode domain detected - potential homoglyph attack")
            self.risk_score += 18
        
        # Excessive hyphens
        hyphen_count = url.count('-')
        if hyphen_count > 5:
            self.findings.append(f"Excessive hyphens ({hyphen_count}) - unusual pattern")
            self.risk_score += 8
    
    def _check_url_shortener(self, parsed):
        """Check for URL shortening services"""
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
            'is.gd', 'buff.ly', 'adf.ly', 'short.link'
        ]
        
        domain = parsed.netloc.lower()
        for shortener in shorteners:
            if shortener in domain:
                self.findings.append(f"URL shortener detected ({shortener}) - destination unknown")
                self.risk_score += 10
                break
    
    def _check_iframe_nesting(self, page_data: dict):
        """Check for suspicious iframe nesting"""
        iframes = page_data.get('iframes', 0)
        
        if iframes > 5:
            self.findings.append(f"Excessive iframes ({iframes}) - possible clickjacking")
            self.risk_score += 15
        elif iframes > 2:
            self.findings.append(f"Multiple iframes ({iframes})")
            self.risk_score += 6
    
    def _check_hidden_elements(self, page_data: dict):
        """Check for hidden or obfuscated elements"""
        html = page_data.get('html', '')
        
        # Check for hidden forms
        hidden_forms = len(re.findall(r'<form[^>]*display:\s*none', html, re.IGNORECASE))
        if hidden_forms > 0:
            self.findings.append(f"Hidden forms detected ({hidden_forms}) - possible data harvesting")
            self.risk_score += 12
        
        # Check for zero-size elements
        zero_size = len(re.findall(r'(width|height):\s*0', html, re.IGNORECASE))
        if zero_size > 3:
            self.findings.append(f"Multiple zero-size elements ({zero_size}) - content hiding")
            self.risk_score += 8
    
    def _check_suspicious_redirects(self, page_data: dict):
        """Check for suspicious redirect patterns"""
        scripts = page_data.get('scripts', [])
        
        redirect_count = 0
        for script in scripts:
            content = script.get('content', '')
            # Check for redirect code
            if re.search(r'(window\.location|location\.href|location\.replace)', content):
                redirect_count += 1
        
        if redirect_count > 3:
            self.findings.append(f"Multiple redirect scripts ({redirect_count}) - possible chain")
            self.risk_score += 10
    
    def _check_domain_impersonation(self, url: str):
        """Check for domain impersonation patterns (e.g., secure-paypal-login, amazon-order-alert)"""
        url_lower = url.lower()
        
        # Known brands that attackers impersonate
        brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'bank', 'banking',
                  'paytm', 'instagram', 'insta', 'steam', 'discord', 'ebay', 'shopify']
        
        # Check for brand + suspicious word patterns (e.g., "paypal-update", "amazon-alert")
        impersonation_patterns = [
            '-update-', '-alert-', '-verify-', '-confirm-', '-recovery-', '-reset-',
            '-help-', '-support-', '-account-', '-login-', '-auth-', '-security-'
        ]
        
        found_impersonations = []
        for brand in brands:
            for pattern in impersonation_patterns:
                if brand in url_lower and pattern in url_lower:
                    found_impersonations.append(f"{brand}{pattern}")
        
        if found_impersonations:
            self.findings.append(f"Domain impersonation detected: {', '.join(found_impersonations[:2])}")
            self.risk_score += 30  # HIGH BOOST for domain impersonation

    def _check_hyphenated_keywords(self, url: str):
        """Check for hyphenated suspicious keyword combinations (e.g., 'secure-login', 'update-verify')"""
        url_lower = url.lower()
        
        # Common suspicious hyphenated patterns
        hyphenated_patterns = [
            'secure-', '-login', '-verify', '-confirm', '-update', '-alert',
            'banking-', 'account-', 'check-', '-session', '-password', '-recovery',
            '-help', '-support', '-service', '-validation', '-authentication'
        ]
        
        # Look for domain with multiple hyphenated keywords
        domain_part = url_lower.split('/')[2]  # Get domain from URL
        
        hyphen_count = 0
        found_patterns = []
        for pattern in hyphenated_patterns:
            if pattern in domain_part:
                hyphen_count += 1
                found_patterns.append(pattern.replace('-', ''))
        
        # Multiple hyphenated patterns = high phishing indicator
        if hyphen_count >= 3:
            self.findings.append(f"Multiple hyphenated keywords in domain: {', '.join(found_patterns[:3])}")
            self.risk_score += 35  # INCREASED BOOST for 3+ patterns
        elif hyphen_count >= 2:
            self.findings.append(f"Multiple hyphenated keywords in domain: {', '.join(found_patterns[:3])}")
            self.risk_score += 25  # BOOST for 2+ hyphenated keywords
        elif hyphen_count == 1 and any(k in domain_part for k in ['verify', 'confirm', 'update', 'alert', 'login', 'secure']):
            self.findings.append(f"Hyphenated phishing keyword: {found_patterns[0]}")
            self.risk_score += 12


# Quick test function
if __name__ == "__main__":
    analyzer = StaticAnalyzer()
    
    # Test with suspicious URL
    test_url = "http://paypal-verify-account.tk/login?redirect=https://192.168.1.1"
    result = analyzer.analyze(test_url)
    
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Findings: {len(result['findings'])}")
    for finding in result['findings']:
        print(f"  - {finding}")
