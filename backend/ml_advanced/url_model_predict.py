"""
Flask Integration Module for URL ML Model

Loads ONNX model and provides fast predictions for backend API.
"""

import os
import numpy as np
import pickle
from typing import Dict, Optional

# Try importing ONNX runtime (fallback to pickle if not available)
try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    print("⚠ Warning: onnxruntime not installed. Using pickle model.")

# Import feature extractor
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ml_training'))
from feature_engineering import URLFeatureExtractor


class URLModelPredictor:
    """
    Production-ready URL malware prediction for Flask backend.
    Uses ONNX for fast inference or falls back to pickle.
    """
    
    def __init__(self, model_dir: str = None):
        """
        Initialize predictor with model files.
        
        Args:
            model_dir: Directory containing model files (default: models/url/)
        """
        if model_dir is None:
            # Get absolute path to models directory
            backend_dir = os.path.dirname(os.path.dirname(__file__))
            model_dir = os.path.join(backend_dir, 'models', 'url')
        
        self.model_dir = model_dir
        self.feature_extractor = URLFeatureExtractor()
        self.model = None
        self.scaler = None
        self.use_onnx = False
        
        # Load model and scaler
        self._load_models()
    
    def _load_models(self) -> None:
        """Load model (ONNX or pickle) and scaler."""
        
        # Paths
        onnx_path = os.path.join(self.model_dir, 'model.onnx')
        pickle_path = os.path.join(self.model_dir, 'model.pkl')
        scaler_path = os.path.join(self.model_dir, 'scaler.pkl')
        
        # Load scaler
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(
                f"Scaler not found: {scaler_path}\n"
                "Please train the model first: python ml_training/train_url_model.py"
            )
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Try loading ONNX model first
        if ONNX_AVAILABLE and os.path.exists(onnx_path):
            try:
                self.model = ort.InferenceSession(onnx_path)
                self.use_onnx = True
                print(f"✓ Loaded ONNX model: {onnx_path}")
            except Exception as e:
                print(f"⚠ Failed to load ONNX model: {e}")
                print("  Falling back to pickle model...")
        
        # Fallback to pickle model
        if self.model is None:
            if not os.path.exists(pickle_path):
                raise FileNotFoundError(
                    f"Model not found: {pickle_path}\n"
                    "Please train the model first: python ml_training/train_url_model.py"
                )
            
            with open(pickle_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"✓ Loaded pickle model: {pickle_path}")
        
        print(f"✓ Loaded scaler: {scaler_path}")
    
    def predict(self, url: str) -> Dict[str, any]:
        """
        Predict whether URL is benign or malicious.
        
        Args:
            url: URL string to analyze
            
        Returns:
            Dictionary with prediction results:
            {
                'score': float (0-1, probability of being malicious),
                'label': 'benign' or 'malicious',
                'confidence': float (0-1)
            }
        """
        try:
            # Extract features
            features = self.feature_extractor.extract_features(url)
            feature_vector = np.array([list(features.values())], dtype=np.float32)
            
            # Scale features
            feature_vector_scaled = self.scaler.transform(feature_vector).astype(np.float32)
            
            # Predict
            if self.use_onnx:
                # ONNX inference
                input_name = self.model.get_inputs()[0].name
                label_name = self.model.get_outputs()[0].name
                proba_name = self.model.get_outputs()[1].name
                
                result = self.model.run(
                    [label_name, proba_name],
                    {input_name: feature_vector_scaled}
                )
                
                prediction = int(result[0][0])
                probabilities = result[1][0]
            else:
                # Pickle model inference
                prediction = self.model.predict(feature_vector_scaled)[0]
                probabilities = self.model.predict_proba(feature_vector_scaled)[0]
            
            # Format result
            malicious_score = float(probabilities[1])
            
            return {
                'score': malicious_score,
                'label': 'malicious' if prediction == 1 else 'benign',
                'confidence': float(probabilities[prediction])
            }
            
        except Exception as e:
            # Return error result
            print(f"Error predicting URL: {e}")
            return {
                'score': 0.5,
                'label': 'unknown',
                'confidence': 0.0,
                'error': str(e)
            }


# Global predictor instance (singleton pattern)
_predictor: Optional[URLModelPredictor] = None


def get_predictor() -> URLModelPredictor:
    """
    Get or create global predictor instance.
    
    Returns:
        URLModelPredictor instance
    """
    global _predictor
    if _predictor is None:
        _predictor = URLModelPredictor()
    return _predictor


def predict_url(url: str) -> Dict[str, any]:
    """
    Convenience function for quick predictions.
    
    Args:
        url: URL string to analyze
        
    Returns:
        Prediction result dictionary
    """
    predictor = get_predictor()
    return predictor.predict(url)


# Test module
if __name__ == "__main__":
    print("="*70)
    print("  URL ML MODEL - FLASK INTEGRATION TEST")
    print("="*70)
    print()
    
    # Initialize predictor
    try:
        predictor = URLModelPredictor()
        print("\n✓ Model loaded successfully!\n")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        sys.exit(1)
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://paypal-verify.xyz/login?user=test",
        "http://192.168.1.1/admin",
        "https://github.com/example/repo"
    ]
    
    print("Testing predictions:")
    print("-" * 70)
    
    for url in test_urls:
        result = predictor.predict(url)
        emoji = "✅" if result['label'] == 'benign' else "⚠️"
        print(f"\n{emoji} {result['label'].upper()}")
        print(f"   URL: {url}")
        print(f"   Score: {result['score']:.4f}")
        print(f"   Confidence: {result['confidence']:.4f}")
    
    print("\n" + "="*70)
    print("Integration test complete!")
