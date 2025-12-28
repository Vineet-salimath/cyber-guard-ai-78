"""
URL ML Model Training Script
Trains a machine learning model for URL-based malware/phishing detection

Usage:
    python ml_training/train_url_model.py

This script:
1. Loads sample URL data (benign + malicious)
2. Extracts features from URLs
3. Trains an ML model (Random Forest or Logistic Regression)
4. Saves trained model for use in url_model_predict.py
"""

import os
import pickle
import logging
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Model output paths
CURRENT_DIR = os.path.dirname(__file__)
MODEL_OUTPUT_DIR = os.path.join(os.path.dirname(CURRENT_DIR), 'ml_advanced')
MODEL_PATH = os.path.join(MODEL_OUTPUT_DIR, 'url_model.pkl')
VECTORIZER_PATH = os.path.join(MODEL_OUTPUT_DIR, 'url_vectorizer.pkl')


class URLFeatureExtractor:
    """Extract features from URLs for ML training"""
    
    @staticmethod
    def extract_features(url: str) -> dict:
        """Extract behavioral features from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            features = {
                'url_length': len(url),
                'domain_length': len(domain),
                'path_length': len(path),
                'dots_count': url.count('.'),
                'hyphens_count': url.count('-'),
                'underscores_count': url.count('_'),
                'slashes_count': url.count('/'),
                'has_https': 1 if parsed.scheme == 'https' else 0,
                'has_at_sign': 1 if '@' in url else 0,
                'has_suspicious_keywords': 1 if any(kw in url.lower() for kw in [
                    'login', 'admin', 'verify', 'confirm', 'account', 'password'
                ]) else 0,
                'subdomain_count': domain.count('.'),
                'digits_count': sum(1 for c in url if c.isdigit()),
            }
            return features
        except:
            return {}


def load_training_data() -> tuple:
    """
    Load or create sample training data
    
    Returns:
        tuple: (urls, labels) where labels are 0 (benign) or 1 (malicious)
    """
    
    # Sample benign URLs
    benign_urls = [
        'https://google.com',
        'https://www.github.com',
        'https://stackoverflow.com/questions',
        'https://www.python.org',
        'https://www.wikipedia.org',
        'https://www.amazon.com',
        'https://www.apple.com',
        'https://www.microsoft.com',
        'https://www.facebook.com',
        'https://www.twitter.com',
        'https://www.linkedin.com',
        'https://www.youtube.com',
        'https://www.reddit.com',
        'https://www.medium.com',
        'https://www.github.io',
        'https://www.npmjs.com',
        'https://www.pypi.org',
        'https://www.docker.com',
        'https://www.kubernetes.io',
    ]
    
    # Sample malicious URLs
    malicious_urls = [
        'http://testsafebrowsing.appspot.com/s/phishing.html',
        'http://testingmcafeesites.com/testcat_be.html',
        'http://sus-paypal-verify.xyz/login',
        'http://amazon-account-update.tk/confirm',
        'http://admin-panel.malware.ru/login',
        'http://secure-update-verify.top',
        'http://confirm-identity.xyz/auth',
        'http://paypal-secure-login.info',
        'http://apple-id-verification.com/signin',
        'http://microsoft-account-recovery.ru',
        'http://email-verification-required.xyz',
        'http://urgent-action-required.tk/verify',
        'http://suspicious-redirect-site.ml/update',
        'http://malicious-download-link.cc/get',
        'http://phishing-page-hosting.ru/admin',
        'http://fake-login-portal.xyz',
        'http://credential-stealer.tk/login',
        'http://data-exfiltration-site.ru',
        'http://malware-distribution-point.xyz',
        'http://ransomware-command-control.ru',
    ]
    
    urls = benign_urls + malicious_urls
    labels = [0] * len(benign_urls) + [1] * len(malicious_urls)
    
    return urls, labels


def train_model():
    """Train URL classification model"""
    
    logger.info("=" * 70)
    logger.info("🚀 URL ML Model Training")
    logger.info("=" * 70)
    
    # Ensure output directory exists
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)
    
    # Load training data
    logger.info("\n📥 Loading training data...")
    urls, labels = load_training_data()
    logger.info(f"   Loaded {len(urls)} URLs")
    logger.info(f"   Benign: {labels.count(0)} | Malicious: {labels.count(1)}")
    
    # Create feature matrix using TF-IDF vectorization
    logger.info("\n⚙️ Extracting features...")
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 3), max_features=100)
    X = vectorizer.fit_transform(urls)
    y = np.array(labels)
    
    logger.info(f"   Feature matrix shape: {X.shape}")
    logger.info(f"   Features: {vectorizer.get_feature_names_out()[:10]}...")
    
    # Split into train/test
    logger.info("\n📊 Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info(f"   Train set: {X_train.shape[0]} samples")
    logger.info(f"   Test set: {X_test.shape[0]} samples")
    
    # Train Random Forest model
    logger.info("\n🤖 Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    logger.info("\n📈 Model Evaluation")
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)
    
    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)
    
    logger.info(f"   Training Accuracy: {train_acc:.4f}")
    logger.info(f"   Test Accuracy: {test_acc:.4f}")
    
    logger.info("\n📋 Classification Report (Test Set):")
    logger.info("\n" + classification_report(y_test, y_pred_test, 
                                             target_names=['Benign', 'Malicious']))
    
    # Save model
    logger.info("\n💾 Saving model...")
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    logger.info(f"   ✅ Model saved: {MODEL_PATH}")
    
    # Save vectorizer
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)
    logger.info(f"   ✅ Vectorizer saved: {VECTORIZER_PATH}")
    
    # Test with sample URLs
    logger.info("\n🧪 Testing trained model...")
    test_urls = [
        'https://google.com',
        'http://testsafebrowsing.appspot.com/s/phishing.html',
    ]
    
    for url in test_urls:
        X_sample = vectorizer.transform([url])
        pred = model.predict(X_sample)[0]
        proba = model.predict_proba(X_sample)[0]
        
        threat_level = 'MALICIOUS' if pred == 1 else 'BENIGN'
        confidence = max(proba)
        
        logger.info(f"   {url}")
        logger.info(f"     → {threat_level} (confidence: {confidence:.2f})")
    
    logger.info("\n" + "=" * 70)
    logger.info("✅ Model training complete!")
    logger.info("=" * 70)
    
    return model, vectorizer


def main():
    """Main training function"""
    try:
        model, vectorizer = train_model()
        logger.info("\n✅ URL ML model is ready to use!")
        logger.info("   Import with: from url_model_predict import predict_url")
        
    except Exception as e:
        logger.error(f"❌ Training failed: {e}")
        raise


if __name__ == '__main__':
    main()
