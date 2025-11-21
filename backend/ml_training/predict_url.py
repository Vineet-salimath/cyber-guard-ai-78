"""
Prediction Module for Testing Trained URL Model

Test the trained model on individual URLs or batches.
"""

import sys
import numpy as np
from feature_engineering import URLFeatureExtractor
from utils import load_pickle, validate_file_exists, print_section


class URLPredictor:
    """
    Loads trained model and makes predictions on URLs.
    """
    
    def __init__(self, model_path: str = "../models/url/model.pkl",
                 scaler_path: str = "../models/url/scaler.pkl"):
        """
        Initialize predictor with trained model and scaler.
        
        Args:
            model_path: Path to trained model pickle file
            scaler_path: Path to fitted scaler pickle file
        """
        print("Loading model and scaler...")
        
        # Validate files exist
        validate_file_exists(model_path, "Model file")
        validate_file_exists(scaler_path, "Scaler file")
        
        # Load model and scaler
        self.model = load_pickle(model_path)
        self.scaler = load_pickle(scaler_path)
        self.feature_extractor = URLFeatureExtractor()
        
        print(f"✓ Model loaded: {model_path}")
        print(f"✓ Scaler loaded: {scaler_path}")
        print(f"✓ Model type: {type(self.model).__name__}")
        print()
        
    def predict_url(self, url: str) -> dict:
        """
        Predict whether a URL is benign or malicious.
        
        Args:
            url: URL string to analyze
            
        Returns:
            Dictionary with prediction results
        """
        # Extract features
        features = self.feature_extractor.extract_features(url)
        feature_vector = np.array([list(features.values())])
        
        # Scale features
        feature_vector_scaled = self.scaler.transform(feature_vector)
        
        # Predict
        prediction = self.model.predict(feature_vector_scaled)[0]
        probability = self.model.predict_proba(feature_vector_scaled)[0]
        
        # Format result
        result = {
            'url': url,
            'prediction': int(prediction),
            'label': 'malicious' if prediction == 1 else 'benign',
            'confidence': float(probability[prediction]),
            'score': float(probability[1]),  # Probability of being malicious
            'benign_probability': float(probability[0]),
            'malicious_probability': float(probability[1])
        }
        
        return result
    
    def predict_batch(self, urls: list) -> list:
        """
        Predict multiple URLs at once.
        
        Args:
            urls: List of URL strings
            
        Returns:
            List of prediction result dictionaries
        """
        results = []
        for url in urls:
            try:
                result = self.predict_url(url)
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'label': 'error'
                })
        return results
    
    def print_result(self, result: dict) -> None:
        """
        Pretty print prediction result.
        
        Args:
            result: Prediction result dictionary
        """
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
            return
        
        # Determine emoji and color
        if result['label'] == 'benign':
            emoji = "✅"
            status = "BENIGN"
        else:
            emoji = "⚠️"
            status = "MALICIOUS"
        
        print(f"\n{emoji} {status}")
        print(f"URL: {result['url']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Malicious Score: {result['score']:.4f}")
        print(f"Probabilities:")
        print(f"  Benign:    {result['benign_probability']:.4f}")
        print(f"  Malicious: {result['malicious_probability']:.4f}")


def main():
    """
    Interactive testing interface.
    """
    print("="*70)
    print("  URL MALWARE DETECTION - PREDICTION TOOL")
    print("="*70)
    print()
    
    # Initialize predictor
    try:
        predictor = URLPredictor()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        print("\nPlease train the model first:")
        print("  python train_url_model.py")
        sys.exit(1)
    
    # Test URLs
    if len(sys.argv) > 1:
        # Predict URLs from command line
        urls = sys.argv[1:]
        print_section("Predictions")
        for url in urls:
            result = predictor.predict_url(url)
            predictor.print_result(result)
    else:
        # Interactive mode with example URLs
        print_section("Testing with Example URLs")
        
        test_urls = [
            "https://www.google.com",
            "https://github.com/GregaVrbancic/Phishing-Dataset",
            "http://paypal-verify.xyz/login?user=test&token=abc123",
            "http://192.168.1.1/admin",
            "https://secure-login.apple-verify.tk/signin",
            "https://amazon.com/products",
            "http://bit.ly/suspicious-link-12345",
            "https://www.microsoft.com/security"
        ]
        
        for url in test_urls:
            result = predictor.predict_url(url)
            predictor.print_result(result)
        
        # Interactive input
        print("\n" + "="*70)
        print("  INTERACTIVE MODE")
        print("="*70)
        print("\nEnter URLs to test (or 'quit' to exit):\n")
        
        while True:
            try:
                url = input("URL: ").strip()
                
                if url.lower() in ['quit', 'exit', 'q']:
                    print("\nGoodbye!")
                    break
                
                if not url:
                    continue
                
                result = predictor.predict_url(url)
                predictor.print_result(result)
                print()
                
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
