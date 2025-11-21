# ML SERVICE FOR MALWARE DETECTION
# Provides machine learning-based threat detection capabilities

import sys
import json
import os
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('MLService')

class URLFeatureExtractor:
    """Extract behavioral features from URLs for ML prediction"""
    
    @staticmethod
    def extract_features(url):
        """
        Extract URL behavioral features
        
        Features:
        - URL length
        - Domain length
        - Number of dots
        - Number of hyphens
        - Number of digits
        - Has HTTPS
        - Is IP address
        - Has suspicious keywords
        - Entropy
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            # Basic metrics
            url_length = len(url)
            domain_length = len(domain)
            path_length = len(path)
            
            # Character counts
            dots_count = url.count('.')
            hyphens_count = url.count('-')
            underscores_count = url.count('_')
            slashes_count = url.count('/')
            digits_count = sum(c.isdigit() for c in url)
            
            # Boolean features
            has_https = 1 if parsed.scheme == 'https' else 0
            is_ip = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
            
            # Suspicious patterns
            suspicious_keywords = [
                'login', 'signin', 'account', 'update', 'verify', 'secure',
                'banking', 'password', 'admin', 'phishing', 'malware',
                'free', 'click', 'download', 'prize', 'winner'
            ]
            has_suspicious = 1 if any(kw in url.lower() for kw in suspicious_keywords) else 0
            
            # URL entropy (measure of randomness)
            entropy = URLFeatureExtractor.calculate_entropy(url)
            
            # Subdomain count
            subdomain_count = domain.count('.') - 1 if domain.count('.') > 0 else 0
            
            features = {
                'url_length': url_length,
                'domain_length': domain_length,
                'path_length': path_length,
                'dots_count': dots_count,
                'hyphens_count': hyphens_count,
                'underscores_count': underscores_count,
                'slashes_count': slashes_count,
                'digits_count': digits_count,
                'has_https': has_https,
                'is_ip': is_ip,
                'has_suspicious': has_suspicious,
                'entropy': entropy,
                'subdomain_count': subdomain_count,
                'query_length': len(parsed.query) if parsed.query else 0
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting URL features: {e}")
            return None
    
    @staticmethod
    def calculate_entropy(string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        from collections import Counter
        import math
        
        counts = Counter(string)
        length = len(string)
        
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )
        
        return round(entropy, 4)


class SimpleMalwareDetector:
    """
    Simple rule-based malware detector
    (In production, replace with trained Random Forest model)
    """
    
    def __init__(self):
        self.model_version = "1.0.0"
        self.algorithm = "Rule-Based + Heuristics"
        
    def predict_url(self, url):
        """
        Predict if URL is malicious based on features
        
        Returns:
            dict: {
                'prediction': 'MALWARE' or 'BENIGN',
                'confidence': float (0-100),
                'probability_malware': float (0-1),
                'probability_benign': float (0-1),
                'risk_score': float (0-100),
                'features': dict
            }
        """
        try:
            # Extract features
            features = URLFeatureExtractor.extract_features(url)
            if not features:
                return self._error_response("Feature extraction failed")
            
            # Calculate risk score based on features
            risk_score = 0
            
            # URL length risk (very long URLs are suspicious)
            if features['url_length'] > 100:
                risk_score += 15
            elif features['url_length'] > 75:
                risk_score += 10
            
            # Domain length risk
            if features['domain_length'] > 50:
                risk_score += 10
            
            # Too many dots (subdomain stuffing)
            if features['dots_count'] > 4:
                risk_score += 15
            
            # IP address instead of domain
            if features['is_ip']:
                risk_score += 20
            
            # No HTTPS
            if not features['has_https']:
                risk_score += 5
            
            # Suspicious keywords
            if features['has_suspicious']:
                risk_score += 25
            
            # High entropy (randomized URLs)
            if features['entropy'] > 4.5:
                risk_score += 15
            
            # Too many hyphens/underscores
            if features['hyphens_count'] + features['underscores_count'] > 5:
                risk_score += 10
            
            # Normalize risk score (0-100)
            risk_score = min(100, risk_score)
            
            # Determine prediction
            if risk_score >= 60:
                prediction = 'MALWARE'
                confidence = risk_score
            else:
                prediction = 'BENIGN'
                confidence = 100 - risk_score
            
            # Calculate probabilities
            prob_malware = risk_score / 100.0
            prob_benign = 1.0 - prob_malware
            
            result = {
                'prediction': prediction,
                'label': prediction,
                'confidence': round(confidence, 2),
                'probability_malware': round(prob_malware, 4),
                'probability_benign': round(prob_benign, 4),
                'risk_score': round(risk_score, 2),
                'features': features,
                'model': {
                    'version': self.model_version,
                    'algorithm': self.algorithm
                },
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"ML Prediction: {prediction} ({confidence:.1f}% confidence) for {url[:50]}...")
            return result
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return self._error_response(str(e))
    
    def _error_response(self, error_msg):
        """Return error response"""
        return {
            'error': error_msg,
            'prediction': 'UNKNOWN',
            'confidence': 0,
            'probability_malware': 0.5,
            'probability_benign': 0.5,
            'risk_score': 50
        }


def main():
    """CLI interface for ML service"""
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python ml_service.py analyze_url <url>")
        print("  python ml_service.py predict <filepath>  (not implemented yet)")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'analyze_url':
        url = sys.argv[2]
        detector = SimpleMalwareDetector()
        result = detector.predict_url(url)
        print(json.dumps(result, indent=2))
        
    elif command == 'predict':
        print(json.dumps({
            'error': 'File prediction not implemented yet',
            'message': 'Currently only URL analysis is supported'
        }))
        sys.exit(1)
        
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == '__main__':
    main()
