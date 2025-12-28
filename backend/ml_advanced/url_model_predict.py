"""
URL ML Model Predictor
Provides machine learning-based URL malware/phishing detection

This module should be trained using: python ml_training/train_url_model.py
Currently provides a baseline predictor until trained model is available.
"""

import pickle
import os
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import logging

logger = logging.getLogger(__name__)

# Model storage path
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'url_model.pkl')
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), 'url_vectorizer.pkl')


class URLMLPredictor:
    """URL-based threat predictor using machine learning"""
    
    def __init__(self):
        """Initialize URL predictor"""
        self.model = None
        self.vectorizer = None
        self.model_loaded = False
        self._load_model()
    
    def _load_model(self):
        """Load trained model from disk if available"""
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
                with open(MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                with open(VECTORIZER_PATH, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                self.model_loaded = True
                logger.info("✅ Trained URL model loaded")
            else:
                logger.warning("⚠️ No trained URL model found - using baseline predictor")
                self.model_loaded = False
        except Exception as e:
            logger.warning(f"⚠️ Failed to load URL model: {e}")
            self.model_loaded = False
    
    def _extract_url_features(self, url: str) -> dict:
        """
        Extract handcrafted features from URL
        
        Features:
        - URL length
        - Domain length
        - Number of dots
        - Number of hyphens
        - Has IP address
        - Has suspicious keywords
        - HTTPS usage
        - URL entropy
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            features = {
                'url_length': len(url),
                'domain_length': len(domain),
                'path_length': len(path),
                'dots_count': url.count('.'),
                'hyphens_count': url.count('-'),
                'underscores_count': url.count('_'),
                'slashes_count': url.count('/'),
                'has_https': 1 if parsed.scheme == 'https' else 0,
                'has_at_sign': 1 if '@' in url else 0,
                'has_suspicious_keywords': self._check_suspicious_keywords(url),
                'subdomain_count': domain.count('.'),
                'digits_count': sum(1 for c in url if c.isdigit()),
            }
            return features
        except Exception as e:
            logger.warning(f"Feature extraction error: {e}")
            return {}
    
    def _check_suspicious_keywords(self, url: str) -> int:
        """Check for suspicious keywords in URL"""
        suspicious = [
            'login', 'admin', 'update', 'verify', 'secure', 'confirm',
            'account', 'password', 'verify', 'auth', 'signin',
            'paypal', 'amazon', 'apple', 'google', 'microsoft'
        ]
        url_lower = url.lower()
        return 1 if any(keyword in url_lower for keyword in suspicious) else 0
    
    def predict(self, url: str) -> dict:
        """
        Predict URL threat level
        
        Args:
            url: URL to predict
            
        Returns:
            dict: {
                'confidence': float (0-1),
                'risk_score': float (0-100),
                'threat_level': str ('benign', 'suspicious', 'malicious'),
                'features': dict
            }
        """
        try:
            # Extract features
            features = self._extract_url_features(url)
            
            # If trained model is available, use it
            if self.model_loaded and self.model and self.vectorizer:
                try:
                    # Vectorize URL
                    url_vector = self.vectorizer.transform([url])
                    
                    # Get prediction and probability
                    prediction = self.model.predict(url_vector)[0]
                    proba = self.model.predict_proba(url_vector)[0]
                    
                    # Map to confidence and risk
                    confidence = max(proba)
                    risk_score = int(proba[1] * 100) if len(proba) > 1 else 0
                    
                except Exception as e:
                    logger.warning(f"Model prediction error: {e} - using baseline")
                    risk_score = self._baseline_predict(features)
                    confidence = 0.7
            else:
                # Use baseline heuristic predictor
                risk_score = self._baseline_predict(features)
                confidence = 0.5
            
            # Determine threat level
            if risk_score >= 70:
                threat_level = 'malicious'
            elif risk_score >= 40:
                threat_level = 'suspicious'
            else:
                threat_level = 'benign'
            
            return {
                'confidence': confidence,
                'risk_score': risk_score,
                'threat_level': threat_level,
                'features': features,
                'model_status': 'trained' if self.model_loaded else 'baseline'
            }
        
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'confidence': 0.0,
                'risk_score': 0,
                'threat_level': 'unknown',
                'features': {},
                'error': str(e)
            }
    
    def _baseline_predict(self, features: dict) -> int:
        """
        Baseline heuristic predictor when ML model unavailable
        
        Returns risk score 0-100 based on URL features
        """
        risk_score = 0
        
        # Long URLs are more suspicious
        if features.get('url_length', 0) > 75:
            risk_score += 10
        
        # Many subdomains suspicious
        if features.get('subdomain_count', 0) > 3:
            risk_score += 15
        
        # HTTP without HTTPS suspicious
        if not features.get('has_https', 0):
            risk_score += 20
        
        # URLs with many special characters suspicious
        special_chars = features.get('hyphens_count', 0) + features.get('underscores_count', 0)
        if special_chars > 5:
            risk_score += 15
        
        # Suspicious keywords increase risk
        if features.get('has_suspicious_keywords', 0):
            risk_score += 25
        
        # IP-based URLs suspicious
        if features.get('has_at_sign', 0):
            risk_score += 30
        
        # Many dots/slashes suspicious
        if features.get('dots_count', 0) > 5:
            risk_score += 10
        
        return min(risk_score, 100)  # Cap at 100


# Global predictor instance
_url_predictor = URLMLPredictor()


def predict_url(url: str) -> dict:
    """
    Predict URL threat level
    
    Usage:
        from url_model_predict import predict_url
        result = predict_url('https://example.com')
        print(result['risk_score'])  # 0-100
        print(result['threat_level'])  # 'benign', 'suspicious', 'malicious'
    
    Args:
        url: URL to analyze
        
    Returns:
        dict: Prediction result with risk_score, threat_level, confidence
    """
    return _url_predictor.predict(url)


if __name__ == '__main__':
    # Test the predictor
    test_urls = [
        'https://google.com',
        'https://testsafebrowsing.appspot.com/s/phishing.html',
        'http://suspicious-login-verify.xyz/update/account',
        'https://amazon.com/verify-account?token=abc123&redirect=http://evil.com'
    ]
    
    predictor = URLMLPredictor()
    
    print("\n🧪 URL Prediction Test")
    print("=" * 60)
    
    for url in test_urls:
        result = predictor.predict(url)
        print(f"\nURL: {url}")
        print(f"  Risk Score: {result['risk_score']}/100")
        print(f"  Threat Level: {result['threat_level']}")
        print(f"  Confidence: {result['confidence']:.2f}")
        print(f"  Model Status: {result.get('model_status', 'unknown')}")
