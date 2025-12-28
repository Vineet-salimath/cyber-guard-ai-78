#!/usr/bin/env python3
"""
Standalone test for URL Risk Classifier
Run without Flask interference
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from url_risk_classifier import URLRiskClassifier

def test_classifier():
    """Test the classifier with known scenarios"""
    classifier = URLRiskClassifier()
    
    test_cases = [
        {
            'url': 'https://malware.wicar.org/data/js_crypto_miner.html',
            'calculated_risk': 15,
            'expected_label': 'MALICIOUS',
            'reason': 'Contains "malware" and "crypto_miner" keywords'
        },
        {
            'url': 'https://www.wicar.org/test-trojan.html',
            'calculated_risk': 5,
            'expected_label': 'MALICIOUS',
            'reason': 'Contains "test-trojan" keyword'
        },
        {
            'url': 'https://suspicious-site.com/download-crack-adobe',
            'calculated_risk': 12,
            'expected_label': 'HIGH_RISK',
            'reason': 'Contains "download-crack" keyword'
        },
        {
            'url': 'https://example.com',
            'calculated_risk': 2,
            'expected_label': 'SAFE',
            'reason': 'No threats detected'
        },
        {
            'url': 'https://www.google.com/search?q=test',
            'calculated_risk': 0,
            'expected_label': 'SAFE',
            'reason': 'Legitimate domain'
        },
        {
            'url': 'https://random-string-xyz.tk/admin.php?id=123&key=abc&val=xyz',
            'calculated_risk': 5,
            'expected_label': 'SUSPICIOUS',
            'reason': 'Suspicious domain pattern + free TLD + excess parameters'
        }
    ]
    
    print("=" * 80)
    print("URL RISK CLASSIFIER TEST SUITE")
    print("=" * 80)
    
    passed = 0
    failed = 0
    
    for i, test in enumerate(test_cases, 1):
        result = classifier.classify(test['url'], test['calculated_risk'])
        
        is_pass = result['label'] == test['expected_label']
        status = "✅ PASS" if is_pass else "❌ FAIL"
        
        print(f"\nTest {i}: {status}")
        print(f"  URL: {test['url']}")
        print(f"  Input Risk: {test['calculated_risk']}%")
        print(f"  Expected: {test['expected_label']}")
        print(f"  Got: {result['label']} ({result['riskScore']}%)")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Reasons: {', '.join(result['reasons'])}")
        print(f"  Note: {test['reason']}")
        
        if is_pass:
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 80)
    
    return passed, failed


if __name__ == '__main__':
    passed, failed = test_classifier()
    exit(0 if failed == 0 else 1)
