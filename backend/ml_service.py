# ML Service - Malware Detection & Feature Extraction
# Provides SimpleMalwareDetector and URLFeatureExtractor classes

import re
import numpy as np
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

class URLFeatureExtractor:
    """Extract features from URLs for machine learning analysis."""
    
    def __init__(self):
        self.features = {}
    
    def extract_features(self, url):
        """
        Extract comprehensive features from a URL.
        
        Features extracted:
        - URL length
        - Domain length
        - Number of dots in domain
        - Number of special characters
        - Presence of IP address
        - Use of HTTPS
        - Number of path levels
        - Suspicious keywords (phishing indicators)
        - Entropy score
        - Character distribution
        """
        features = {}
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            # Basic URL features
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['path_length'] = len(path)
            features['path_count'] = len([p for p in path.split('/') if p])
            
            # Domain features
            features['dot_count'] = domain.count('.')
            features['hyphen_count'] = domain.count('-')
            features['underscore_count'] = domain.count('_')
            
            # Suspicious patterns
            features['has_ip'] = 1 if self._is_ip_address(domain) else 0
            features['uses_https'] = 1 if parsed.scheme == 'https' else 0
            features['has_at_symbol'] = 1 if '@' in url else 0
            features['has_query'] = 1 if parsed.query else 0
            features['has_fragment'] = 1 if parsed.fragment else 0
            
            # Suspicious keywords in domain
            suspicious_keywords = ['login', 'verify', 'confirm', 'account', 'update', 
                                  'secure', 'bank', 'paypal', 'amazon', 'apple', 'google']
            domain_lower = domain.lower()
            features['suspicious_keywords'] = sum(1 for kw in suspicious_keywords if kw in domain_lower)
            
            # Character distribution
            features['digit_ratio'] = sum(1 for c in domain if c.isdigit()) / len(domain) if domain else 0
            features['alpha_ratio'] = sum(1 for c in domain if c.isalpha()) / len(domain) if domain else 0
            
            # Entropy score (measure of randomness/obfuscation)
            features['entropy_score'] = self._calculate_entropy(domain)
            
            # Check for encoding/obfuscation
            features['has_percent_encoding'] = 1 if '%' in url else 0
            features['has_hex_encoding'] = 1 if re.search(r'\\x[0-9a-f]{2}', url, re.IGNORECASE) else 0
            
            # URL structure anomalies
            features['repeated_subdomains'] = self._count_repeated_subdomains(domain)
            
            # Suspicious TLDs
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'download']
            tld = domain.split('.')[-1] if '.' in domain else domain
            features['suspicious_tld'] = 1 if tld.lower() in suspicious_tlds else 0
            
            # Dynamic content indicators
            features['has_data_uri'] = 1 if 'data:' in url else 0
            features['has_javascript_uri'] = 1 if 'javascript:' in url.lower() else 0
            
        except Exception as e:
            logger.warning(f"Error extracting features from URL: {e}")
            features = {k: 0 for k in range(20)}  # Return zero features on error
        
        self.features = features
        return features
    
    def _is_ip_address(self, domain):
        """Check if domain is an IP address."""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text (randomness measure)."""
        if not text:
            return 0
        
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0
        text_len = len(text)
        for count in char_counts.values():
            prob = count / text_len
            entropy -= prob * np.log2(prob)
        
        return entropy
    
    def _count_repeated_subdomains(self, domain):
        """Count repeated subdomains (e.g., 'sub.sub.example.com')."""
        parts = domain.split('.')
        if len(parts) < 2:
            return 0
        
        repeated = 0
        for i in range(len(parts) - 1):
            if parts[i] == parts[i + 1]:
                repeated += 1
        
        return repeated
    
    def get_features_vector(self, url):
        """Get feature vector as numpy array for ML model input."""
        features = self.extract_features(url)
        # Return features in consistent order
        feature_names = [
            'url_length', 'domain_length', 'path_length', 'path_count',
            'dot_count', 'hyphen_count', 'underscore_count', 'has_ip',
            'uses_https', 'has_at_symbol', 'has_query', 'has_fragment',
            'suspicious_keywords', 'digit_ratio', 'alpha_ratio', 'entropy_score',
            'has_percent_encoding', 'has_hex_encoding', 'repeated_subdomains',
            'suspicious_tld'
        ]
        
        vector = np.array([features.get(name, 0) for name in feature_names], dtype=float)
        return vector


class SimpleMalwareDetector:
    """
    Simple rule-based malware detector for URLs.
    Provides baseline detection until ML models are trained.
    """
    
    def __init__(self):
        self.feature_extractor = URLFeatureExtractor()
        self.malicious_patterns = self._load_malicious_patterns()
        self.benign_domains = self._load_benign_domains()
    
    def _load_malicious_patterns(self):
        """Load patterns commonly found in malicious URLs."""
        return {
            'javascript_execution': r'javascript:.*\(',
            'data_uri_execution': r'data:text/html.*<script',
            'suspicious_redirect': r'(redirect|redir|r\.php\?|go\.php)',
            'base64_payload': r'(base64|b64|encoded)',
            'suspicious_encoding': r'%2e|%2f|%5c',
            'url_shortener': r'(bit\.ly|tinyurl|short\.link|ow\.ly)',
            'obfuscated_domain': r'^[a-z0-9]{20,}',  # Very long random domain
            'homograph_attack': r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP instead of domain
        }
    
    def _load_benign_domains(self):
        """Load list of known benign domains."""
        return {
            'google.com', 'facebook.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'amazon.com', 'microsoft.com', 'apple.com',
            'youtube.com', 'twitter.com', 'linkedin.com', 'reddit.com',
            'example.com', 'localhost', '127.0.0.1'
        }
    
    def predict(self, url, return_features=False):
        """
        Predict if URL is malicious.
        
        Returns:
            {
                'is_malicious': bool,
                'confidence': float (0-1),
                'reasons': [list of detection reasons],
                'score': float (0-100),
                'features': dict (if return_features=True)
            }
        """
        result = {
            'is_malicious': False,
            'confidence': 0.0,
            'reasons': [],
            'score': 0.0,
        }
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(url)
            
            if return_features:
                result['features'] = features
            
            # Check against benign domains first
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
            
            if domain in self.benign_domains:
                result['score'] = 0.0
                result['confidence'] = 0.95
                return result
            
            # Check for malicious patterns
            malicious_count = 0
            for pattern_name, pattern in self.malicious_patterns.items():
                if re.search(pattern, url, re.IGNORECASE):
                    malicious_count += 1
                    result['reasons'].append(f"Pattern detected: {pattern_name}")
            
            # Feature-based analysis
            score = 0.0
            
            # IP address instead of domain = high risk
            if features['has_ip']:
                score += 25
                result['reasons'].append("Using IP address instead of domain")
            
            # No HTTPS = medium risk
            if not features['uses_https']:
                score += 10
                result['reasons'].append("Not using HTTPS")
            
            # @ symbol in URL = phishing indicator
            if features['has_at_symbol']:
                score += 30
                result['reasons'].append("Contains @ symbol (phishing indicator)")
            
            # High entropy = obfuscation
            if features['entropy_score'] > 4.5:
                score += 15
                result['reasons'].append("High entropy (possible obfuscation)")
            
            # Suspicious keywords
            if features['suspicious_keywords'] > 0:
                score += 10 * features['suspicious_keywords']
                result['reasons'].append(f"Suspicious keywords detected: {features['suspicious_keywords']}")
            
            # Suspicious TLD
            if features['suspicious_tld']:
                score += 20
                result['reasons'].append("Using suspicious TLD")
            
            # Percent encoding in URL
            if features['has_percent_encoding']:
                score += 5
                result['reasons'].append("Contains percent encoding")
            
            # JavaScript or data URI execution
            if features['has_javascript_uri'] or features['has_data_uri']:
                score += 40
                result['reasons'].append("JavaScript or data URI execution detected")
            
            # Pattern matches
            score += min(malicious_count * 15, 50)
            
            # Determine if malicious
            result['score'] = min(score, 100.0)
            result['is_malicious'] = score > 40  # Threshold: 40+
            result['confidence'] = min(score / 100.0, 1.0)
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            result['score'] = 0.0
            result['confidence'] = 0.0
            result['reasons'].append(f"Error during analysis: {e}")
        
        return result
    
    def analyze_batch(self, urls):
        """Analyze multiple URLs in batch."""
        results = {}
        for url in urls:
            results[url] = self.predict(url)
        return results


# Module-level convenience functions
_detector = None
_feature_extractor = None

def get_detector():
    """Get global detector instance."""
    global _detector
    if _detector is None:
        _detector = SimpleMalwareDetector()
    return _detector

def get_feature_extractor():
    """Get global feature extractor instance."""
    global _feature_extractor
    if _feature_extractor is None:
        _feature_extractor = URLFeatureExtractor()
    return _feature_extractor

def predict_url(url):
    """Convenience function to predict single URL."""
    return get_detector().predict(url)

def extract_url_features(url):
    """Convenience function to extract URL features."""
    return get_feature_extractor().extract_features(url)

# Initialize on module load
logger.info("SimpleMalwareDetector initialized (rule-based baseline detection)")
