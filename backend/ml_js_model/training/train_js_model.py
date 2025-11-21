"""
JavaScript Malware Detection Model Training Script

Trains XGBoost/RandomForest model on JS malware dataset.
"""

import os
import sys
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import pickle
import json
from datetime import datetime

# Try to import XGBoost (optional)
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("⚠ XGBoost not available. Using RandomForest instead.")
    print("  Install with: pip install xgboost")

# Add parent paths
sys.path.append(os.path.dirname(__file__))
from dataset_loader import JSDatasetLoader


class JSModelTrainer:
    """
    Trains JavaScript malware detection model.
    """
    
    def __init__(self, use_xgboost: bool = True):
        """
        Initialize trainer.
        
        Args:
            use_xgboost: Whether to use XGBoost (falls back to RandomForest)
        """
        self.use_xgboost = use_xgboost and XGBOOST_AVAILABLE
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.metrics = {}
        
    def create_model(self):
        """Create the model (XGBoost or RandomForest)."""
        if self.use_xgboost:
            print("Using XGBoost Classifier")
            self.model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                random_state=42,
                n_jobs=-1,
                eval_metric='logloss'
            )
        else:
            print("Using RandomForest Classifier")
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=42,
                n_jobs=-1,
                verbose=1
            )
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> None:
        """
        Train the model.
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        print("\n" + "="*70)
        print("  MODEL TRAINING")
        print("="*70)
        print(f"Model type: {type(self.model).__name__}")
        print(f"Training samples: {len(X_train):,}")
        print(f"Features: {X_train.shape[1]}")
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
            Dictionary of metrics
        """
        print("\n" + "="*70)
        print("  MODEL EVALUATION")
        print("="*70)
        
        # Predictions
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        self.metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1_score': f1_score(y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, y_pred_proba)
        }
        
        # Print metrics
        print("\nModel Performance Metrics:")
        print("-" * 40)
        for metric, value in self.metrics.items():
            print(f"  {metric:15s}: {value:.4f}")
        print("-" * 40)
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(f"                Predicted")
        print(f"              Benign  Malicious")
        print(f"Actual Benign    {cm[0][0]:6d}  {cm[0][1]:6d}")
        print(f"       Malicious {cm[1][0]:6d}  {cm[1][1]:6d}")
        
        # Classification report
        print("\nDetailed Classification Report:")
        print(classification_report(y_test, y_pred,
                                   target_names=['Benign', 'Malicious'],
                                   digits=4))
        
        # Feature importance (top 10)
        if hasattr(self.model, 'feature_importances_') and self.feature_names:
            print("\nTop 10 Most Important Features:")
            importances = self.model.feature_importances_
            indices = np.argsort(importances)[::-1][:10]
            for i, idx in enumerate(indices, 1):
                print(f"  {i:2d}. {self.feature_names[idx]:30s}: {importances[idx]:.4f}")
        
        return self.metrics
    
    def save_model(self, model_path: str, scaler_path: str,
                   metadata_path: str) -> None:
        """
        Save trained model, scaler, and metadata.
        
        Args:
            model_path: Path to save model pickle
            scaler_path: Path to save scaler pickle
            metadata_path: Path to save metadata JSON
        """
        print("\n" + "="*70)
        print("  SAVING MODELS")
        print("="*70)
        
        # Create directory
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save model
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"✓ Model saved: {model_path}")
        print(f"  Size: {os.path.getsize(model_path) / 1024 / 1024:.2f} MB")
        
        # Save scaler
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        print(f"✓ Scaler saved: {scaler_path}")
        
        # Save metadata
        metadata = {
            'model_type': type(self.model).__name__,
            'training_date': datetime.now().isoformat(),
            'metrics': self.metrics,
            'feature_names': self.feature_names,
            'n_features': len(self.feature_names) if self.feature_names else 0
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✓ Metadata saved: {metadata_path}")
    
    def export_onnx(self, onnx_path: str) -> None:
        """
        Export model to ONNX format.
        
        Args:
            onnx_path: Path to save ONNX model
        """
        try:
            from skl2onnx import convert_sklearn
            from skl2onnx.common.data_types import FloatTensorType
            
            print("\n" + "-"*70)
            print("Exporting to ONNX format...")
            
            # Define input type
            n_features = len(self.feature_names)
            initial_type = [('float_input', FloatTensorType([None, n_features]))]
            
            # Convert
            onnx_model = convert_sklearn(
                self.model,
                initial_types=initial_type,
                target_opset=12
            )
            
            # Save
            with open(onnx_path, "wb") as f:
                f.write(onnx_model.SerializeToString())
            
            print(f"✓ ONNX model saved: {onnx_path}")
            print(f"  Size: {os.path.getsize(onnx_path) / 1024 / 1024:.2f} MB")
            
        except ImportError:
            print("\n⚠ Warning: skl2onnx not installed. Skipping ONNX export.")
            print("  Install with: pip install skl2onnx onnxruntime")
        except Exception as e:
            print(f"\n⚠ Warning: ONNX export failed: {e}")


def main():
    """Main training pipeline."""
    print("="*70)
    print("  JAVASCRIPT MALWARE DETECTION - MODEL TRAINING")
    print("="*70)
    
    # Step 1: Load dataset
    loader = JSDatasetLoader(
        malicious_dir='../data/malicious',
        benign_dir='../data/benign'
    )
    
    try:
        # Try to load real dataset
        X, y = loader.load_dataset(max_malicious=1000, max_benign=1000)
    except Exception as e:
        print(f"\n⚠ Could not load real dataset: {e}")
        print("\nUsing sample dataset...")
        
        # Create and load sample dataset
        sample_csv = '../data/sample_dataset.csv'
        if not os.path.exists(sample_csv):
            loader.create_sample_dataset(sample_csv)
        
        # Load sample data
        df = pd.read_csv(sample_csv)
        y = df['label'].values
        X = df.drop('label', axis=1)
    
    # Step 2: Train/test split
    print("\n" + "="*70)
    print("  DATA SPLITTING")
    print("="*70)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train set: {len(X_train):,} samples")
    print(f"Test set:  {len(X_test):,} samples")
    
    # Step 3: Feature scaling
    print("\n" + "="*70)
    print("  FEATURE SCALING")
    print("="*70)
    trainer = JSModelTrainer(use_xgboost=XGBOOST_AVAILABLE)
    
    print("Fitting scaler on training data...")
    X_train_scaled = trainer.scaler.fit_transform(X_train)
    X_test_scaled = trainer.scaler.transform(X_test)
    print("✓ Scaling complete")
    
    # Store feature names
    trainer.feature_names = list(X.columns)
    
    # Step 4: Train model
    trainer.create_model()
    trainer.train(X_train_scaled, y_train)
    
    # Step 5: Evaluate
    metrics = trainer.evaluate(X_test_scaled, y_test)
    
    # Step 6: Save models
    model_dir = '../../models/js'
    trainer.save_model(
        model_path=os.path.join(model_dir, 'js_model.pkl'),
        scaler_path=os.path.join(model_dir, 'js_scaler.pkl'),
        metadata_path=os.path.join(model_dir, 'js_metadata.json')
    )
    
    # Step 7: Export ONNX
    trainer.export_onnx(os.path.join(model_dir, 'js_model.onnx'))
    
    # Final summary
    print("\n" + "="*70)
    print("  TRAINING COMPLETE")
    print("="*70)
    print(f"✓ Model trained successfully!")
    print(f"✓ Test Accuracy: {metrics['accuracy']:.2%}")
    print(f"✓ Test Precision: {metrics['precision']:.2%}")
    print(f"✓ Test Recall: {metrics['recall']:.2%}")
    print(f"✓ Test F1-Score: {metrics['f1_score']:.2%}")
    print(f"✓ ROC AUC: {metrics['roc_auc']:.4f}")
    
    print(f"\n📁 Model files saved to: {model_dir}/")
    print("  - js_model.pkl (pickle format)")
    print("  - js_model.onnx (ONNX format)")
    print("  - js_scaler.pkl (feature scaler)")
    print("  - js_metadata.json (training info)")
    
    print("\n🚀 Next steps:")
    print("  1. Test model: python ../inference/js_infer.py")
    print("  2. Integrate into Flask backend")
    print("="*70)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
