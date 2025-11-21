"""
LAYER B: OWASP TOP 10 CHECKS
Passive security header and vulnerability detection (NO ACTIVE SCANNING)
"""

import re
from urllib.parse import urlparse

class OWASPChecker:
    """Performs passive OWASP Top 10 security checks"""
    
    def __init__(self):
        self.findings = []
        self.risk_score = 0.0
        self.vulnerability_count = 0
    
    def analyze(self, url: str, page_data: dict = None) -> dict:
        """
        Perform OWASP security analysis
        
        Args:
            url: URL being analyzed
            page_data: Page content with headers, HTML, scripts
        
        Returns:
            dict: Security findings and risk score
        """
        self.findings = []
        self.risk_score = 0.0
        self.vulnerability_count = 0
        
        if not page_data:
            return {
                'risk_score': 0,
                'findings': ['No page data available for OWASP checks'],
                'vulnerabilities': [],
                'status': 'skipped'
            }
        
        try:
            headers = page_data.get('headers', {})
            html = page_data.get('html', '')
            scripts = page_data.get('scripts', [])
            
            # Run all OWASP checks
            self._check_csp(headers)
            self._check_x_frame_options(headers)
            self._check_hsts(headers, url)
            self._check_cookies(headers)
            self._check_cors(headers)
            self._check_mixed_content(url, html)
            self._check_open_redirects(html, scripts)
            self._check_reflected_xss(html)
            self._check_exposed_secrets(html)
            self._check_insecure_dependencies(html, scripts)
            
            # Normalize risk score
            self.risk_score = min(100, max(0, self.risk_score))
            
            return {
                'risk_score': round(self.risk_score, 2),
                'findings': self.findings,
                'vulnerability_count': self.vulnerability_count,
                'status': 'completed'
            }
            
        except Exception as e:
            return {
                'risk_score': 0,
                'findings': [f"OWASP analysis error: {str(e)}"],
                'vulnerability_count': 0,
                'status': 'error'
            }
    
    def _check_csp(self, headers: dict):
        """Check Content Security Policy"""
        csp = headers.get('content-security-policy', '').lower()
        
        if not csp:
            self.findings.append("⚠️ Missing Content-Security-Policy header - XSS risk")
            self.risk_score += 12
            self.vulnerability_count += 1
            return
        
        # Check for unsafe directives
        if "'unsafe-inline'" in csp:
            self.findings.append("⚠️ CSP allows 'unsafe-inline' - reduced XSS protection")
            self.risk_score += 8
            self.vulnerability_count += 1
        
        if "'unsafe-eval'" in csp:
            self.findings.append("⚠️ CSP allows 'unsafe-eval' - code injection risk")
            self.risk_score += 8
            self.vulnerability_count += 1
        
        if "*" in csp and "default-src" in csp:
            self.findings.append("⚠️ CSP uses wildcard (*) - overly permissive")
            self.risk_score += 6
    
    def _check_x_frame_options(self, headers: dict):
        """Check X-Frame-Options header"""
        xfo = headers.get('x-frame-options', '').lower()
        csp_frame = 'frame-ancestors' in headers.get('content-security-policy', '').lower()
        
        if not xfo and not csp_frame:
            self.findings.append("⚠️ Missing X-Frame-Options - clickjacking risk")
            self.risk_score += 10
            self.vulnerability_count += 1
        elif xfo == 'allow' or xfo == 'allowall':
            self.findings.append("⚠️ X-Frame-Options set to ALLOW - clickjacking possible")
            self.risk_score += 8
            self.vulnerability_count += 1
    
    def _check_hsts(self, headers: dict, url: str):
        """Check HTTP Strict Transport Security"""
        if not url.startswith('https://'):
            return  # HSTS only relevant for HTTPS
        
        hsts = headers.get('strict-transport-security', '').lower()
        
        if not hsts:
            self.findings.append("⚠️ Missing HSTS header - downgrade attack risk")
            self.risk_score += 10
            self.vulnerability_count += 1
            return
        
        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                self.findings.append(f"⚠️ HSTS max-age too short ({max_age}s) - should be ≥1 year")
                self.risk_score += 5
        
        # Check includeSubDomains
        if 'includesubdomains' not in hsts:
            self.findings.append("ℹ️ HSTS missing includeSubDomains - subdomains unprotected")
            self.risk_score += 3
    
    def _check_cookies(self, headers: dict):
        """Check cookie security flags"""
        set_cookie = headers.get('set-cookie', '').lower()
        
        if not set_cookie:
            return  # No cookies to check
        
        issues = []
        
        # Check for HttpOnly flag
        if 'httponly' not in set_cookie:
            issues.append("missing HttpOnly flag")
            self.risk_score += 8
            self.vulnerability_count += 1
        
        # Check for Secure flag
        if 'secure' not in set_cookie:
            issues.append("missing Secure flag")
            self.risk_score += 8
            self.vulnerability_count += 1
        
        # Check for SameSite
        if 'samesite' not in set_cookie:
            issues.append("missing SameSite attribute")
            self.risk_score += 6
            self.vulnerability_count += 1
        elif 'samesite=none' in set_cookie:
            issues.append("SameSite=None (CSRF risk)")
            self.risk_score += 5
        
        if issues:
            self.findings.append(f"⚠️ Insecure cookie settings: {', '.join(issues)}")
    
    def _check_cors(self, headers: dict):
        """Check CORS policy"""
        acao = headers.get('access-control-allow-origin', '').lower()
        
        if acao == '*':
            self.findings.append("⚠️ CORS allows all origins (*) - data exposure risk")
            self.risk_score += 10
            self.vulnerability_count += 1
        
        acac = headers.get('access-control-allow-credentials', '').lower()
        if acac == 'true' and acao == '*':
            self.findings.append("🚨 CORS allows credentials with wildcard origin - critical risk")
            self.risk_score += 20
            self.vulnerability_count += 1
    
    def _check_mixed_content(self, url: str, html: str):
        """Check for mixed content (HTTPS page loading HTTP resources)"""
        if not url.startswith('https://'):
            return
        
        # Find HTTP resources in HTTPS page
        http_resources = re.findall(r'src=["\']http://[^"\']+["\']', html, re.IGNORECASE)
        http_resources += re.findall(r'href=["\']http://[^"\']+["\']', html, re.IGNORECASE)
        
        count = len(set(http_resources))
        if count > 0:
            self.findings.append(f"⚠️ Mixed content detected ({count} HTTP resources on HTTPS page)")
            self.risk_score += 12
            self.vulnerability_count += 1
    
    def _check_open_redirects(self, html: str, scripts: list):
        """Check for open redirect vulnerabilities"""
        redirect_patterns = [
            r'location\.href\s*=\s*["\']?\??redirect=',
            r'location\.href\s*=\s*["\']?\??url=',
            r'window\.location\s*=\s*["\']?\??goto=',
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url='
        ]
        
        found_redirects = []
        
        # Check HTML
        for pattern in redirect_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                found_redirects.append("HTML redirect")
                break
        
        # Check scripts
        for script in scripts:
            content = script.get('content', '')
            for pattern in redirect_patterns[:3]:  # JS patterns only
                if re.search(pattern, content, re.IGNORECASE):
                    found_redirects.append("JS redirect")
                    break
        
        if found_redirects:
            self.findings.append(f"⚠️ Potential open redirect found - phishing/XSS risk")
            self.risk_score += 15
            self.vulnerability_count += 1
    
    def _check_reflected_xss(self, html: str):
        """Check for reflected XSS patterns"""
        xss_patterns = [
            r'<script[^>]*>[^<]*document\.location[^<]*</script>',
            r'<script[^>]*>[^<]*document\.cookie[^<]*</script>',
            r'<script[^>]*>[^<]*window\.location[^<]*</script>',
            r'onerror\s*=\s*["\'][^"\']*alert\(',
            r'onload\s*=\s*["\'][^"\']*alert\(',
            r'javascript:[^"\']*alert\('
        ]
        
        xss_found = []
        for pattern in xss_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                xss_found.append(pattern)
        
        if xss_found:
            self.findings.append(f"🚨 Possible reflected XSS patterns detected - critical risk")
            self.risk_score += 25
            self.vulnerability_count += 1
    
    def _check_exposed_secrets(self, html: str):
        """Check for exposed sensitive information"""
        secrets = []
        
        # API keys
        if re.search(r'(api[_-]?key|apikey)\s*[=:]\s*["\'][a-zA-Z0-9]{20,}', html, re.IGNORECASE):
            secrets.append("API keys")
            self.risk_score += 20
        
        # AWS credentials
        if re.search(r'AKIA[0-9A-Z]{16}', html):
            secrets.append("AWS credentials")
            self.risk_score += 25
        
        # Private keys
        if 'BEGIN PRIVATE KEY' in html or 'BEGIN RSA PRIVATE KEY' in html:
            secrets.append("private keys")
            self.risk_score += 30
        
        # Database credentials
        if re.search(r'(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}', html, re.IGNORECASE):
            secrets.append("passwords")
            self.risk_score += 18
        
        # Email addresses
        email_count = len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', html))
        if email_count > 5:
            secrets.append(f"{email_count} email addresses")
            self.risk_score += 5
        
        if secrets:
            self.findings.append(f"🚨 Exposed sensitive data: {', '.join(secrets)}")
            self.vulnerability_count += 1
    
    def _check_insecure_dependencies(self, html: str, scripts: list):
        """Check for insecure or suspicious CDN/library links"""
        suspicious_cdns = [
            r'http://',  # Non-HTTPS CDN
            r'\.ru/',
            r'\.cn/',
            r'free-?cdn',
            r'cdn-?free',
            r'analytics-?tracker'
        ]
        
        all_sources = []
        
        # Extract script sources from HTML
        all_sources += re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        
        # Extract from script objects
        for script in scripts:
            src = script.get('src', '')
            if src:
                all_sources.append(src)
        
        suspicious_found = []
        for src in all_sources:
            for pattern in suspicious_cdns:
                if re.search(pattern, src, re.IGNORECASE):
                    suspicious_found.append(src[:50] + '...' if len(src) > 50 else src)
                    break
        
        if suspicious_found:
            count = len(suspicious_found)
            self.findings.append(f"⚠️ Suspicious JavaScript sources detected ({count}) - malware risk")
            self.risk_score += min(15, count * 5)
            self.vulnerability_count += 1


# Quick test
if __name__ == "__main__":
    checker = OWASPChecker()
    
    # Test with mock page data
    test_data = {
        'headers': {},  # No security headers
        'html': '<script>window.location = "?redirect=" + document.location</script>',
        'scripts': []
    }
    
    result = checker.analyze("https://example.com", test_data)
    print(f"OWASP Risk Score: {result['risk_score']}/100")
    print(f"Vulnerabilities: {result['vulnerability_count']}")
    for finding in result['findings']:
        print(f"  {finding}")
