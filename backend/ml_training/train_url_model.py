"""
Model Training Script for URL Malware Detection

Trains a RandomForest classifier and exports to pickle and ONNX formats.
"""

import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
from preprocess import DataPreprocessor
from utils import (
    save_pickle, save_json, print_section, print_metrics,
    get_timestamp, format_size, get_file_size
)


class URLModelTrainer:
    """
    Trains and evaluates URL malware detection model.
    """
    
    def __init__(self, n_estimators: int = 100, max_depth: int = 20, 
                 random_state: int = 42):
        """
        Initialize trainer with model hyperparameters.
        
        Args:
            n_estimators: Number of trees in random forest
            max_depth: Maximum depth of trees
            random_state: Random seed for reproducibility
        """
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,  # Use all CPU cores
            verbose=1
        )
        self.metrics = {}
        
    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> None:
        """
        Train the model on training data.
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        print_section("Model Training")
        print(f"Model: RandomForestClassifier")
        print(f"  n_estimators: {self.model.n_estimators}")
        print(f"  max_depth: {self.model.max_depth}")
        print(f"  Training samples: {len(X_train):,}")
        print("\nTraining in progress...")
        
        self.model.fit(X_train, y_train)
        
        print("\n✓ Training complete!")
        
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """
        Evaluate model on test data.
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary of evaluation metrics
        """
        print_section("Model Evaluation")
        
        # Predictions
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        self.metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1_score': f1_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_pred_proba)
        }
        
        # Print metrics
        print_metrics(self.metrics)
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(f"                Predicted")
        print(f"              Benign  Phishing")
        print(f"Actual Benign    {cm[0][0]:6d}  {cm[0][1]:6d}")
        print(f"       Phishing  {cm[1][0]:6d}  {cm[1][1]:6d}")
        
        # Classification report
        print("\nDetailed Classification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Benign', 'Phishing'],
                                   digits=4))
        
        return self.metrics
    
    def save_model_pickle(self, filepath: str) -> None:
        """
        Save model to pickle format.
        
        Args:
            filepath: Path to save pickle file
        """
        save_pickle(self.model, filepath)
        size = format_size(get_file_size(filepath))
        print(f"  Model size: {size}")
        
    def save_model_onnx(self, filepath: str, feature_names: list) -> None:
        """
        Save model to ONNX format for fast inference.
        
        Args:
            filepath: Path to save ONNX file
            feature_names: List of feature names
        """
        try:
            from skl2onnx import convert_sklearn
            from skl2onnx.common.data_types import FloatTensorType
            
            print("\nConverting model to ONNX format...")
            
            # Define input type
            n_features = len(feature_names)
            initial_type = [('float_input', FloatTensorType([None, n_features]))]
            
            # Convert to ONNX
            onnx_model = convert_sklearn(
                self.model, 
                initial_types=initial_type,
                target_opset=12
            )
            
            # Save ONNX model
            with open(filepath, "wb") as f:
                f.write(onnx_model.SerializeToString())
            
            print(f"✓ Saved ONNX: {filepath}")
            size = format_size(get_file_size(filepath))
            print(f"  Model size: {size}")
            
        except ImportError:
            print("\n⚠ Warning: skl2onnx not installed. Skipping ONNX export.")
            print("  Install with: pip install skl2onnx onnxruntime")
            print("  Model saved as pickle only.")
        except Exception as e:
            print(f"\n⚠ Warning: ONNX export failed: {e}")
            print("  Model saved as pickle only.")
    
    def save_metadata(self, filepath: str, feature_names: list, 
                     dataset_info: dict) -> None:
        """
        Save model metadata and training information.
        
        Args:
            filepath: Path to save JSON metadata
            feature_names: List of feature names
            dataset_info: Information about training dataset
        """
        metadata = {
            'model_type': 'RandomForestClassifier',
            'model_params': {
                'n_estimators': self.model.n_estimators,
                'max_depth': self.model.max_depth,
                'random_state': self.model.random_state
            },
            'metrics': self.metrics,
            'feature_names': feature_names,
            'n_features': len(feature_names),
            'training_date': get_timestamp(),
            'dataset_info': dataset_info
        }
        
        save_json(metadata, filepath)


def main(dataset_path: str = "dataset_full.csv"):
    """
    Complete training pipeline.
    
    Args:
        dataset_path: Path to dataset CSV file
    """
    print("="*70)
    print("  URL MALWARE DETECTION - MODEL TRAINING")
    print("="*70)
    print(f"\nDataset: {dataset_path}\n")
    
    # Step 1: Preprocess data
    preprocessor = DataPreprocessor(dataset_path)
    data = preprocessor.preprocess_pipeline(
        test_size=0.2,
        save_scaler=True,
        scaler_path="../models/url/scaler.pkl"
    )
    
    # Step 2: Train model
    trainer = URLModelTrainer(
        n_estimators=100,
        max_depth=20,
        random_state=42
    )
    
    trainer.train(data['X_train'], data['y_train'])
    
    # Step 3: Evaluate model
    metrics = trainer.evaluate(data['X_test'], data['y_test'])
    
    # Step 4: Save models
    print_section("Saving Models")
    
    # Save pickle
    trainer.save_model_pickle("../models/url/model.pkl")
    
    # Save ONNX
    trainer.save_model_onnx("../models/url/model.onnx", data['feature_names'])
    
    # Save metadata
    dataset_info = {
        'total_samples': len(data['y_train']) + len(data['y_test']),
        'train_samples': len(data['y_train']),
        'test_samples': len(data['y_test']),
        'benign_samples': int((data['y_train'] == 0).sum() + (data['y_test'] == 0).sum()),
        'phishing_samples': int((data['y_train'] == 1).sum() + (data['y_test'] == 1).sum())
    }
    
    trainer.save_metadata("../models/url/metadata.json", data['feature_names'], 
                         dataset_info)
    
    # Final summary
    print_section("Training Complete")
    print(f"✓ Model trained successfully!")
    print(f"✓ Test Accuracy: {metrics['accuracy']:.2%}")
    print(f"✓ Test Precision: {metrics['precision']:.2%}")
    print(f"✓ Test Recall: {metrics['recall']:.2%}")
    print(f"✓ Test F1-Score: {metrics['f1_score']:.2%}")
    print(f"✓ ROC AUC: {metrics['roc_auc']:.4f}")
    
    print("\n📁 Model files saved to: ../models/url/")
    print("  - model.pkl (pickle format)")
    print("  - model.onnx (ONNX format)")
    print("  - scaler.pkl (feature scaler)")
    print("  - metadata.json (training info)")
    
    print("\n🚀 Next steps:")
    print("  1. Test predictions: python predict_url.py")
    print("  2. Integrate into Flask: See url_model_predict.py")
    print("="*70)


if __name__ == "__main__":
    # Get dataset path from command line or use default
    dataset_path = sys.argv[1] if len(sys.argv) > 1 else "dataset_full.csv"
    
    try:
        main(dataset_path)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
