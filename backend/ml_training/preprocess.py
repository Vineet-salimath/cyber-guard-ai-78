"""
Data Preprocessing Module for URL Malware Detection

Loads the phishing dataset, extracts features, and prepares train/test splits.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from feature_engineering import URLFeatureExtractor
from utils import save_pickle, print_section, validate_file_exists
import sys


class DataPreprocessor:
    """
    Handles data loading, feature extraction, and preprocessing for ML training.
    """
    
    def __init__(self, dataset_path: str):
        """
        Initialize preprocessor.
        
        Args:
            dataset_path: Path to dataset_full.csv
        """
        self.dataset_path = dataset_path
        self.feature_extractor = URLFeatureExtractor()
        self.scaler = StandardScaler()
        
    def load_dataset(self) -> pd.DataFrame:
        """
        Load the phishing dataset from CSV.
        
        Returns:
            DataFrame with 'url' and 'status' columns
        """
        print_section("Loading Dataset")
        
        # Validate file exists
        validate_file_exists(self.dataset_path, "Dataset file")
        
        # Load CSV
        print(f"Reading: {self.dataset_path}")
        df = pd.read_csv(self.dataset_path)
        
        print(f"✓ Loaded {len(df):,} rows")
        print(f"✓ Columns: {list(df.columns)}")
        
        # Verify required columns exist
        if 'url' not in df.columns or 'status' not in df.columns:
            raise ValueError(
                "Dataset must contain 'url' and 'status' columns.\n"
                f"Found columns: {list(df.columns)}"
            )
        
        # Extract only required columns
        df = df[['url', 'status']].copy()
        
        # Remove any null values
        initial_count = len(df)
        df = df.dropna()
        dropped = initial_count - len(df)
        if dropped > 0:
            print(f"✓ Dropped {dropped} rows with null values")
        
        # Display class distribution
        print("\nClass Distribution:")
        print(f"  Benign (0):  {(df['status'] == 0).sum():,} samples")
        print(f"  Phishing (1): {(df['status'] == 1).sum():,} samples")
        
        return df
    
    def extract_features_from_dataset(self, df: pd.DataFrame) -> tuple:
        """
        Extract features from all URLs in dataset.
        
        Args:
            df: DataFrame with 'url' and 'status' columns
            
        Returns:
            Tuple of (X: feature matrix, y: labels)
        """
        print_section("Feature Extraction")
        
        print(f"Extracting features from {len(df):,} URLs...")
        
        # Extract features for all URLs
        features_list = []
        for idx, url in enumerate(df['url']):
            if (idx + 1) % 10000 == 0:
                print(f"  Processed {idx + 1:,} / {len(df):,} URLs...")
            
            try:
                features = self.feature_extractor.extract_features(url)
                features_list.append(features)
            except Exception as e:
                print(f"  Warning: Failed to extract features for URL at index {idx}: {e}")
                # Use zero features as fallback
                features_list.append({
                    name: 0 for name in self.feature_extractor.get_feature_names()
                })
        
        # Convert to DataFrame
        X = pd.DataFrame(features_list)
        y = df['status'].values
        
        print(f"\n✓ Feature extraction complete!")
        print(f"✓ Feature matrix shape: {X.shape}")
        print(f"✓ Number of features: {X.shape[1]}")
        print(f"\nFeature names:")
        for i, name in enumerate(X.columns, 1):
            print(f"  {i:2d}. {name}")
        
        return X, y
    
    def split_data(self, X: pd.DataFrame, y: np.ndarray, test_size: float = 0.2, 
                   random_state: int = 42) -> tuple:
        """
        Split data into train and test sets.
        
        Args:
            X: Feature matrix
            y: Labels
            test_size: Proportion of test set (default 0.2 = 20%)
            random_state: Random seed for reproducibility
            
        Returns:
            Tuple of (X_train, X_test, y_train, y_test)
        """
        print_section("Data Splitting")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        print(f"Train/Test split: {int((1-test_size)*100)}/{int(test_size*100)}")
        print(f"\nTraining set:")
        print(f"  Total samples: {len(X_train):,}")
        print(f"  Benign:        {(y_train == 0).sum():,}")
        print(f"  Phishing:      {(y_train == 1).sum():,}")
        
        print(f"\nTest set:")
        print(f"  Total samples: {len(X_test):,}")
        print(f"  Benign:        {(y_test == 0).sum():,}")
        print(f"  Phishing:      {(y_test == 1).sum():,}")
        
        return X_train, X_test, y_train, y_test
    
    def scale_features(self, X_train: pd.DataFrame, X_test: pd.DataFrame) -> tuple:
        """
        Scale features using StandardScaler (fit on train, transform both).
        
        Args:
            X_train: Training features
            X_test: Test features
            
        Returns:
            Tuple of (X_train_scaled, X_test_scaled)
        """
        print_section("Feature Scaling")
        
        print("Fitting StandardScaler on training data...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        print("Transforming test data...")
        X_test_scaled = self.scaler.transform(X_test)
        
        print(f"✓ Scaling complete!")
        print(f"  Train shape: {X_train_scaled.shape}")
        print(f"  Test shape:  {X_test_scaled.shape}")
        
        return X_train_scaled, X_test_scaled
    
    def preprocess_pipeline(self, test_size: float = 0.2, 
                           save_scaler: bool = True,
                           scaler_path: str = None) -> dict:
        """
        Complete preprocessing pipeline from raw data to train/test splits.
        
        Args:
            test_size: Proportion of test set
            save_scaler: Whether to save the fitted scaler
            scaler_path: Path to save scaler (default: ../models/url/scaler.pkl)
            
        Returns:
            Dictionary with all preprocessed data and metadata
        """
        # Load dataset
        df = self.load_dataset()
        
        # Extract features
        X, y = self.extract_features_from_dataset(df)
        
        # Split data
        X_train, X_test, y_train, y_test = self.split_data(X, y, test_size=test_size)
        
        # Scale features
        X_train_scaled, X_test_scaled = self.scale_features(X_train, X_test)
        
        # Save scaler
        if save_scaler:
            if scaler_path is None:
                scaler_path = "../models/url/scaler.pkl"
            save_pickle(self.scaler, scaler_path)
        
        # Return all data
        return {
            'X_train': X_train_scaled,
            'X_test': X_test_scaled,
            'y_train': y_train,
            'y_test': y_test,
            'feature_names': self.feature_extractor.get_feature_names(),
            'scaler': self.scaler
        }


if __name__ == "__main__":
    """
    Test preprocessing pipeline.
    """
    # Dataset path (adjust if needed)
    DATASET_PATH = "dataset_full.csv"
    
    if len(sys.argv) > 1:
        DATASET_PATH = sys.argv[1]
    
    print("="*70)
    print("  URL MALWARE DETECTION - DATA PREPROCESSING")
    print("="*70)
    print(f"\nDataset: {DATASET_PATH}\n")
    
    # Initialize preprocessor
    preprocessor = DataPreprocessor(DATASET_PATH)
    
    # Run preprocessing pipeline
    data = preprocessor.preprocess_pipeline(
        test_size=0.2,
        save_scaler=True,
        scaler_path="../models/url/scaler.pkl"
    )
    
    # Summary
    print_section("Preprocessing Complete")
    print(f"✓ Training samples: {data['X_train'].shape[0]:,}")
    print(f"✓ Test samples:     {data['X_test'].shape[0]:,}")
    print(f"✓ Number of features: {len(data['feature_names'])}")
    print(f"✓ Scaler saved")
    print("\nReady for model training!")
    print("Run: python train_url_model.py")
