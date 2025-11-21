"""
Feature Engineering Module for URL-based Malware Detection

Extracts comprehensive features from URLs for machine learning classification.
All features are numerical and ML-ready.
"""

import re
import math
from urllib.parse import urlparse
from typing import Dict, Any


class URLFeatureExtractor:
    """
    Extracts 15+ numerical features from URLs for ML training and prediction.
    """
    
    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = {
        '.xyz', '.top', '.click', '.link', '.club', '.work', '.gq', '.ml', 
        '.cf', '.tk', '.ga', '.zip', '.review', '.country', '.kim', '.cricket',
        '.science', '.work', '.party', '.gdn', '.trade'
    }
    
    # Phishing keywords
    PHISHING_KEYWORDS = {
        'login', 'verify', 'secure', 'update', 'confirm', 'account', 'banking',
        'signin', 'ebay', 'paypal', 'amazon', 'apple', 'microsoft', 'suspended',
        'limited', 'expires', 'verification', 'password', 'credit', 'ssn'
    }
    
    def __init__(self):
        """Initialize the feature extractor."""
        pass
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """
        Extract all features from a single URL.
        
        Args:
            url: The URL string to analyze
            
        Returns:
            Dictionary with all numerical features
        """
        features = {}
        
        # Clean URL
        url = url.strip().lower()
        
        # Basic length features
        features['url_length'] = len(url)
        
        # Character count features
        features['num_dots'] = url.count('.')
        features['num_slashes'] = url.count('/')
        features['num_question'] = url.count('?')
        features['num_equals'] = url.count('=')
        features['num_ampersand'] = url.count('&')
        features['num_percent'] = url.count('%')
        features['num_at'] = url.count('@')
        features['num_dash'] = url.count('-')
        features['num_underscore'] = url.count('_')
        
        # Digit analysis
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['digit_ratio'] = features['num_digits'] / max(len(url), 1)
        
        # Special character ratio
        special_chars = sum(not c.isalnum() and c not in ['/', '.', ':'] for c in url)
        features['special_char_ratio'] = special_chars / max(len(url), 1)
        
        # Contains IP address?
        features['has_ip'] = int(self._contains_ip(url))
        
        # Suspicious TLD?
        features['has_suspicious_tld'] = int(self._has_suspicious_tld(url))
        
        # URL entropy (randomness measure)
        features['entropy'] = self._calculate_entropy(url)
        
        # HTTPS check
        features['is_https'] = int(url.startswith('https://'))
        
        # Keyword presence
        features['phishing_keyword_count'] = self._count_phishing_keywords(url)
        
        # Contains @ symbol (common in phishing)
        features['has_at_symbol'] = int('@' in url)
        
        # Subdomain count
        features['subdomain_count'] = self._count_subdomains(url)
        
        # Path length
        parsed = urlparse(url)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        
        # Domain length
        features['domain_length'] = len(parsed.netloc)
        
        return features
    
    def _contains_ip(self, url: str) -> bool:
        """
        Check if URL contains an IP address instead of domain name.
        
        Args:
            url: URL string
            
        Returns:
            True if IP address detected
        """
        # IPv4 pattern
        ipv4_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ipv4_pattern, url))
    
    def _has_suspicious_tld(self, url: str) -> bool:
        """
        Check if URL uses a suspicious top-level domain.
        
        Args:
            url: URL string
            
        Returns:
            True if suspicious TLD found
        """
        return any(url.endswith(tld) for tld in self.SUSPICIOUS_TLDS)
    
    def _calculate_entropy(self, url: str) -> float:
        """
        Calculate Shannon entropy of URL (measures randomness).
        Higher entropy = more random = potentially suspicious.
        
        Args:
            url: URL string
            
        Returns:
            Entropy value (0 to ~8)
        """
        if not url:
            return 0.0
        
        # Character frequency
        freq = {}
        for char in url:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(url)
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _count_phishing_keywords(self, url: str) -> int:
        """
        Count number of phishing-related keywords in URL.
        
        Args:
            url: URL string
            
        Returns:
            Number of phishing keywords found
        """
        count = 0
        url_lower = url.lower()
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in url_lower:
                count += 1
        return count
    
    def _count_subdomains(self, url: str) -> int:
        """
        Count number of subdomains in URL.
        Example: sub1.sub2.example.com has 2 subdomains
        
        Args:
            url: URL string
            
        Returns:
            Number of subdomains
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            # Remove port if present
            domain = domain.split(':')[0]
            # Count dots (subdomains = dots - 1 for TLD)
            dots = domain.count('.')
            return max(0, dots - 1)
        except:
            return 0
    
    def extract_features_batch(self, urls: list) -> list:
        """
        Extract features from multiple URLs efficiently.
        
        Args:
            urls: List of URL strings
            
        Returns:
            List of feature dictionaries
        """
        return [self.extract_features(url) for url in urls]
    
    def get_feature_names(self) -> list:
        """
        Get list of all feature names in order.
        
        Returns:
            List of feature name strings
        """
        return [
            'url_length', 'num_dots', 'num_slashes', 'num_question', 'num_equals',
            'num_ampersand', 'num_percent', 'num_at', 'num_dash', 'num_underscore',
            'num_digits', 'digit_ratio', 'special_char_ratio', 'has_ip',
            'has_suspicious_tld', 'entropy', 'is_https', 'phishing_keyword_count',
            'has_at_symbol', 'subdomain_count', 'path_length', 'query_length',
            'domain_length'
        ]


if __name__ == "__main__":
    # Test the feature extractor
    extractor = URLFeatureExtractor()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://paypal-verify.xyz/login?user=test&token=abc123",
        "http://192.168.1.1/admin",
        "https://legitimate-site.com/products"
    ]
    
    print("Feature Extraction Test\n" + "="*60)
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extractor.extract_features(url)
        for key, value in features.items():
            print(f"  {key:25s}: {value}")
    
    print(f"\n\nTotal features: {len(extractor.get_feature_names())}")
    print(f"Feature names: {extractor.get_feature_names()}")
