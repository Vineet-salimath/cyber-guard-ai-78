"""
URL ML MODEL TRAINING SCRIPT

This script trains a machine learning model for URL-based malware detection.

Features extracted:
- URL length, domain length, path length
- Character distribution (digits, special chars, etc.)
- Lexical patterns (entropy, TLD, subdomains)
- Suspicious keyword presence
- IP address usage

Model: Random Forest Classifier (sklearn)
Output: url_model.pkl

Dataset Requirements:
- Phishing URLs: https://www.phishtank.com/developer_info.php
- Malicious URLs: https://github.com/mitchellkrogza/Phishing.Database
- Benign URLs: Alexa Top 1M or Cisco Umbrella Top 1M

Format:
url,label
https://example.com,benign
https://phishing-site.tk,malicious
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import pickle
import re
import math
from urllib.parse import urlparse
from collections import Counter
import os

class URLFeatureExtractor:
    """Extract features from URLs for ML training"""
    
    @staticmethod
    def extract_features(url):
        """
        Extract comprehensive features from URL
        
        Returns:
            dict: Feature dictionary
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            features = {
                # Length features
                'url_length': len(url),
                'domain_length': len(domain),
                'path_length': len(path),
                
                # Character counts
                'digit_count': sum(c.isdigit() for c in url),
                'letter_count': sum(c.isalpha() for c in url),
                'special_char_count': sum(not c.isalnum() for c in url),
                
                # Ratios
                'digit_ratio': sum(c.isdigit() for c in url) / max(len(url), 1),
                'letter_ratio': sum(c.isalpha() for c in url) / max(len(url), 1),
                
                # Pattern features
                'dot_count': url.count('.'),
                'hyphen_count': url.count('-'),
                'underscore_count': url.count('_'),
                'slash_count': url.count('/'),
                'at_symbol': 1 if '@' in url else 0,
                
                # Security features
                'has_https': 1 if parsed.scheme == 'https' else 0,
                'has_port': 1 if ':' in domain and not domain.endswith((':443', ':80')) else 0,
                'is_ip': 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', domain) else 0,
                
                # Subdomain features
                'subdomain_count': domain.count('.') - 1 if '.' in domain else 0,
                
                # Entropy
                'url_entropy': URLFeatureExtractor.calculate_entropy(url),
                'domain_entropy': URLFeatureExtractor.calculate_entropy(domain),
                
                # TLD features
                'tld_length': len(domain.split('.')[-1]) if '.' in domain else 0,
                
                # Suspicious patterns
                'has_suspicious_tld': 1 if any(tld in domain.lower() for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0,
                'has_suspicious_keywords': 1 if any(kw in url.lower() for kw in ['login', 'verify', 'account', 'secure', 'update']) else 0
            }
            
            return features
            
        except Exception as e:
            print(f"Error extracting features from {url}: {e}")
            return None
    
    @staticmethod
    def calculate_entropy(text):
        """Calculate Shannon entropy"""
        if not text:
            return 0
        counter = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        return entropy


def load_dataset(benign_file, malicious_file):
    """
    Load and combine benign and malicious URL datasets
    
    Args:
        benign_file: Path to benign URLs file (one URL per line)
        malicious_file: Path to malicious URLs file (one URL per line)
    
    Returns:
        DataFrame with 'url' and 'label' columns
    """
    print("📥 Loading datasets...")
    
    # Load benign URLs
    if os.path.exists(benign_file):
        with open(benign_file, 'r') as f:
            benign_urls = [line.strip() for line in f if line.strip()]
        benign_df = pd.DataFrame({
            'url': benign_urls,
            'label': ['benign'] * len(benign_urls)
        })
        print(f"   ✓ Loaded {len(benign_urls)} benign URLs")
    else:
        print(f"   ⚠️ Benign file not found: {benign_file}")
        benign_df = pd.DataFrame(columns=['url', 'label'])
    
    # Load malicious URLs
    if os.path.exists(malicious_file):
        with open(malicious_file, 'r') as f:
            malicious_urls = [line.strip() for line in f if line.strip()]
        malicious_df = pd.DataFrame({
            'url': malicious_urls,
            'label': ['malicious'] * len(malicious_urls)
        })
        print(f"   ✓ Loaded {len(malicious_urls)} malicious URLs")
    else:
        print(f"   ⚠️ Malicious file not found: {malicious_file}")
        malicious_df = pd.DataFrame(columns=['url', 'label'])
    
    # Combine datasets
    df = pd.concat([benign_df, malicious_df], ignore_index=True)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"   ✓ Total URLs: {len(df)}")
    print(f"   ✓ Benign: {len(df[df['label'] == 'benign'])}")
    print(f"   ✓ Malicious: {len(df[df['label'] == 'malicious'])}")
    
    return df


def extract_features_from_dataframe(df):
    """Extract features for all URLs in dataframe"""
    print("\n🔍 Extracting features...")
    
    extractor = URLFeatureExtractor()
    features_list = []
    
    for idx, row in df.iterrows():
        if idx % 1000 == 0:
            print(f"   Processing {idx}/{len(df)}...")
        
        url = row['url']
        features = extractor.extract_features(url)
        
        if features:
            features['label'] = row['label']
            features_list.append(features)
    
    features_df = pd.DataFrame(features_list)
    print(f"   ✓ Extracted features for {len(features_df)} URLs")
    
    return features_df


def train_model(features_df):
    """Train Random Forest model"""
    print("\n🤖 Training model...")
    
    # Separate features and labels
    X = features_df.drop('label', axis=1)
    y = features_df['label']
    
    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    print(f"   Training set: {len(X_train)} samples")
    print(f"   Test set: {len(X_test)} samples")
    
    # Train Random Forest
    print("   Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\n📊 Evaluating model...")
    y_pred = model.predict(X_test)
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance
    print("\n🔝 Top 10 Important Features:")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(feature_importance.head(10))
    
    return model, le, X.columns.tolist()


def save_model(model, label_encoder, feature_names, output_path='../models/url_model.pkl'):
    """Save trained model"""
    print(f"\n💾 Saving model to {output_path}...")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    model_package = {
        'model': model,
        'label_encoder': label_encoder,
        'feature_names': feature_names
    }
    
    with open(output_path, 'wb') as f:
        pickle.dump(model_package, f)
    
    print(f"   ✓ Model saved successfully")
    print(f"   Size: {os.path.getsize(output_path) / 1024:.2f} KB")


# MAIN TRAINING PIPELINE
if __name__ == "__main__":
    print("="*80)
    print("URL MALWARE DETECTION - MODEL TRAINING")
    print("="*80)
    
    # STEP 1: Download datasets (instructions)
    print("\n📚 DATASET REQUIREMENTS:")
    print("   1. Benign URLs: Download from Cisco Umbrella Top 1M")
    print("      https://umbrella.cisco.com/blog/cisco-umbrella-1-million")
    print("   2. Malicious URLs: Download from PhishTank or GitHub repos")
    print("      - https://www.phishtank.com/developer_info.php")
    print("      - https://github.com/mitchellkrogza/Phishing.Database")
    print("   3. Place files in:")
    print("      - ../datasets/benign_urls.txt")
    print("      - ../datasets/malicious_urls.txt")
    print("\n   Format: One URL per line\n")
    
    # Check if datasets exist
    benign_file = '../datasets/benign_urls.txt'
    malicious_file = '../datasets/malicious_urls.txt'
    
    if not os.path.exists(benign_file) or not os.path.exists(malicious_file):
        print("⚠️  Dataset files not found!")
        print("   Creating sample datasets for demonstration...")
        
        # Create sample datasets
        os.makedirs('../datasets', exist_ok=True)
        
        # Sample benign URLs
        sample_benign = [
            "https://google.com",
            "https://github.com",
            "https://stackoverflow.com",
            "https://amazon.com",
            "https://microsoft.com"
        ] * 20  # 100 samples
        
        with open(benign_file, 'w') as f:
            f.write('\n'.join(sample_benign))
        
        # Sample malicious URLs
        sample_malicious = [
            "http://phishing-site.tk/login",
            "http://192.168.1.1/secure-verify",
            "http://paypal-verify.suspicious.com",
            "http://amazon-update-account.ml",
            "http://secure-login-microsoft.ga"
        ] * 20  # 100 samples
        
        with open(malicious_file, 'w') as f:
            f.write('\n'.join(sample_malicious))
        
        print("   ✓ Sample datasets created")
    
    # STEP 2: Load dataset
    df = load_dataset(benign_file, malicious_file)
    
    if len(df) < 100:
        print("\n⚠️  Warning: Dataset too small for production use!")
        print("   Minimum recommended: 10,000 URLs (5,000 benign + 5,000 malicious)")
        print("   Continuing with demonstration...")
    
    # STEP 3: Extract features
    features_df = extract_features_from_dataframe(df)
    
    # STEP 4: Train model
    model, label_encoder, feature_names = train_model(features_df)
    
    # STEP 5: Save model
    save_model(model, label_encoder, feature_names)
    
    print("\n" + "="*80)
    print("✅ TRAINING COMPLETE!")
    print("="*80)
    print("\nNext steps:")
    print("1. Test the model with: python test_url_model.py")
    print("2. Deploy to production by copying url_model.pkl to backend/ml/models/")
    print("3. Retrain with larger datasets for better accuracy")
