"""
URL ML MODEL INFERENCE

Loads trained url_model.pkl and performs predictions.
"""

import pickle
import os

class URLInference:
    def __init__(self, model_path='../models/url_model.pkl'):
        self.model = None
        self.label_encoder = None
        self.feature_names = None
        
        if os.path.exists(model_path):
            self.load_model(model_path)
    
    def load_model(self, path):
        """Load trained model"""
        with open(path, 'rb') as f:
            package = pickle.load(f)
            self.model = package['model']
            self.label_encoder = package['label_encoder']
            self.feature_names = package['feature_names']
    
    def predict(self, url_features):
        """
        Predict URL classification
        
        Returns:
            dict: {'label': str, 'score': float, 'status': str}
        """
        if not self.model:
            return {'status': 'model_missing', 'label': 'unknown', 'score': 0}
        
        try:
            # Extract features (reuse from training script)
            from train_url import URLFeatureExtractor
            features = URLFeatureExtractor.extract_features(url_features)
            
            # Predict
            pred = self.model.predict([list(features.values())])
            prob = self.model.predict_proba([list(features.values())])
            
            label = self.label_encoder.inverse_transform(pred)[0]
            score = float(max(prob[0]))
            
            return {
                'status': 'ok',
                'label': label,
                'score': score
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
