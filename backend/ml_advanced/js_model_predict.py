"""
Flask Integration Module for JavaScript Malware Detection

Provides production-ready predictions for Flask backend.
"""

import os
import sys

# Add inference path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'ml_js_model', 'inference'))

try:
    from js_infer import JSModelInference
    JS_MODEL_AVAILABLE = True
    _predictor = None
except ImportError as e:
    print(f"⚠ JS Model not available: {e}")
    JS_MODEL_AVAILABLE = False
    _predictor = None


def get_predictor():
    """Get or create global predictor instance (singleton)."""
    global _predictor
    if _predictor is None and JS_MODEL_AVAILABLE:
        model_dir = os.path.join(
            os.path.dirname(__file__), '..', 'models', 'js'
        )
        _predictor = JSModelInference(model_dir=model_dir)
    return _predictor


def predict_js(js_code: str) -> dict:
    """
    Predict if JavaScript code is malicious.
    
    Args:
        js_code: JavaScript code string
        
    Returns:
        Dictionary with:
        {
            'score': float (0-1, probability of malicious),
            'label': 'benign' | 'malicious_js' | 'obfuscated',
            'status': 'ok' | 'error'
        }
    """
    if not JS_MODEL_AVAILABLE:
        return {
            'score': 0.0,
            'label': 'unknown',
            'status': 'error',
            'error': 'JS model not available'
        }
    
    predictor = get_predictor()
    if predictor is None:
        return {
            'score': 0.0,
            'label': 'unknown',
            'status': 'error',
            'error': 'Failed to load predictor'
        }
    
    return predictor.predict(js_code)


# Test module
if __name__ == "__main__":
    print("="*70)
    print("  JS ML MODEL - FLASK INTEGRATION TEST")
    print("="*70)
    print()
    
    if not JS_MODEL_AVAILABLE:
        print("❌ JS Model not available")
        print("\nPlease train the model first:")
        print("  cd backend/ml_js_model/training")
        print("  python train_js_model.py")
        sys.exit(1)
    
    # Initialize
    try:
        predictor = get_predictor()
        print("✓ Model loaded successfully!\n")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        sys.exit(1)
    
    # Test
    test_js = """
    eval(atob("bWFsd2FyZQ=="));
    setTimeout(function() {
        document.write("<iframe src='evil.com'></iframe>");
    }, 1000);
    """
    
    result = predict_js(test_js)
    
    print("Test Prediction:")
    print("-" * 70)
    print(f"  Label: {result['label']}")
    print(f"  Score: {result['score']:.4f}")
    print(f"  Status: {result['status']}")
    
    print("\n" + "="*70)
    print("Integration test complete!")
