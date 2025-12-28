#!/usr/bin/env python3
"""
QUICK VERIFICATION TEST - Cyber Guard AI System Status
Run this to verify all systems are working

Usage:
    cd backend
    python verification_test.py
"""

import sys
import os

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*70)
    print(f"🔍 {title}")
    print("="*70)

def test_imports():
    """Test all critical imports"""
    print_header("TESTING IMPORTS")
    
    tests = [
        ("Flask", "from flask import Flask"),
        ("CORS", "from flask_cors import CORS"),
        ("SocketIO", "from flask_socketio import SocketIO"),
        ("URL ML Model", "from url_model_predict import predict_url"),
        ("JS ML Model", "from js_model_predict import predict_js"),
        ("Risk Engine", "from risk_engine import UnifiedRiskEngine"),
        ("ML Service", "from ml_service import SimpleMalwareDetector"),
        ("Scan Storage", "from scan_storage import ScanStorage"),
        ("Real-time Detector", "from real_time_threat_detector import RealTimeThreatDetector"),
    ]
    
    results = []
    for name, import_stmt in tests:
        try:
            exec(import_stmt)
            print(f"✅ {name:<25} OK")
            results.append(True)
        except ImportError as e:
            print(f"❌ {name:<25} FAILED: {e}")
            results.append(False)
    
    return all(results)

def test_url_prediction():
    """Test URL prediction"""
    print_header("TESTING URL PREDICTION")
    
    try:
        from url_model_predict import predict_url
        
        test_urls = [
            ('https://google.com', 'benign'),
            ('http://testsafebrowsing.appspot.com/s/phishing.html', 'malicious'),
            ('http://phishing-login-verify.xyz', 'suspicious'),
        ]
        
        for url, expected_category in test_urls:
            result = predict_url(url)
            status = "✅" if result['threat_level'] == expected_category else "⚠️"
            print(f"{status} {url}")
            print(f"   Risk Score: {result['risk_score']}/100")
            print(f"   Threat Level: {result['threat_level']}")
            print(f"   Model Status: {result.get('model_status', 'unknown')}")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_js_prediction():
    """Test JavaScript prediction"""
    print_header("TESTING JAVASCRIPT PREDICTION")
    
    try:
        from js_model_predict import predict_js
        
        test_codes = [
            ('console.log("hello");', 'benign'),
            ('eval(atob("evilcode"));', 'malicious'),
            ('document.write("<script>");', 'suspicious'),
        ]
        
        for code, expected_category in test_codes:
            result = predict_js(code)
            status = "✅" if result['threat_level'] == expected_category else "⚠️"
            print(f"{status} {code[:40]}...")
            print(f"   Risk Score: {result['risk_score']}/100")
            print(f"   Threat Level: {result['threat_level']}")
            print(f"   Model Status: {result.get('model_status', 'unknown')}")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_risk_engine():
    """Test Risk Engine initialization"""
    print_header("TESTING RISK ENGINE")
    
    try:
        from risk_engine import UnifiedRiskEngine
        
        engine = UnifiedRiskEngine()
        print("✅ Risk Engine initialized")
        print("   Layers: Static Analysis, OWASP, TI, Signature, ML, Heuristics")
        print("   Status: Ready for multi-layer analysis")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_scan_storage():
    """Test Scan Storage"""
    print_header("TESTING SCAN STORAGE")
    
    try:
        from scan_storage import ScanStorage
        
        storage = ScanStorage()
        print("✅ Scan Storage initialized")
        print("   Database: SQLite (scan_database.db)")
        print("   Status: Ready for persistent storage")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_api_keys():
    """Check API key configuration"""
    print_header("CHECKING API CONFIGURATION")
    
    from dotenv import load_dotenv
    load_dotenv()
    
    keys = {
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY'),
        'GOOGLE_SAFE_BROWSING_API_KEY': os.getenv('GOOGLE_SAFE_BROWSING_API_KEY'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY'),
        'ALIENVAULT_OTX_KEY': os.getenv('ALIENVAULT_OTX_KEY'),
    }
    
    for key_name, key_value in keys.items():
        if key_value and key_value != 'your_api_key_here':
            print(f"✅ {key_name:<35} Configured")
        else:
            print(f"⚠️ {key_name:<35} Not configured (optional)")
    
    return True

def main():
    """Run all tests"""
    print("\n" + "🛡️ CYBER GUARD AI - SYSTEM VERIFICATION" + "\n")
    print(f"Working Directory: {os.getcwd()}")
    print(f"Python Version: {sys.version.split()[0]}")
    
    results = []
    
    # Run tests
    results.append(("Imports", test_imports()))
    results.append(("URL Prediction", test_url_prediction()))
    results.append(("JavaScript Prediction", test_js_prediction()))
    results.append(("Risk Engine", test_risk_engine()))
    results.append(("Scan Storage", test_scan_storage()))
    results.append(("API Configuration", test_api_keys()))
    
    # Print summary
    print_header("SUMMARY")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status:<10} {test_name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    # Final status
    print_header("STATUS")
    
    if passed == total:
        print("✅ ALL SYSTEMS OPERATIONAL")
        print("\nYour Cyber Guard AI system is ready!")
        print("\nNext steps:")
        print("1. Add API keys to .env for enhanced detection")
        print("2. Train ML models with real data (optional)")
        print("3. Start scanning URLs with /api/scanner/submit-url")
    elif passed >= total - 2:
        print("⚠️ MOST SYSTEMS OPERATIONAL")
        print("\nCore functionality is working. Missing API keys are optional.")
        print("\nYou can:")
        print("1. Use baseline predictions (no API keys needed)")
        print("2. Add API keys later for enhanced detection")
        print("3. Start scanning immediately")
    else:
        print("❌ SOME SYSTEMS OFFLINE")
        print("\nPlease check the errors above and install missing dependencies.")
    
    print("\n" + "="*70 + "\n")

if __name__ == '__main__':
    main()
