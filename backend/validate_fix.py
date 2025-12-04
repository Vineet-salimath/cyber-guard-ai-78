#!/usr/bin/env python3
"""
COMPREHENSIVE PHISHING DETECTION FIX VALIDATION
Tests the risk scoring engine against known phishing and malicious URLs
"""

from risk_engine import UnifiedRiskEngine
import json
from datetime import datetime

def print_header(text):
    print(f"\n{'='*80}")
    print(f">> {text}")
    print(f"{'='*80}\n")

def print_result(url, result, expected_classification):
    """Print a formatted test result"""
    classification = result['final_classification']
    risk_score = result['overall_risk']
    
    # Determine pass/fail
    passed = classification == expected_classification
    status = "PASS" if passed else "FAIL"
    
    print(f"{'='*40}")
    print(f"URL: {url}")
    print(f"Expected: {expected_classification} | Got: {classification}")
    print(f"Risk Score: {risk_score}/100 | Risk Level: {result['risk_level']}")
    print(f"Duration: {result['analysis_duration']}s")
    print(f"Status: [{status}]")
    print()
    
    return passed

# Initialize engine
print_header("INITIALIZING RISK ENGINE")
engine = UnifiedRiskEngine()
print("OK: Risk engine initialized successfully\n")

# Test cases with expected results
test_cases = [
    # KNOWN PHISHING URLS (should be MALICIOUS)
    {
        'url': 'http://testsafebrowsing.appspot.com/s/phishing.html',
        'expected': 'MALICIOUS',
        'description': 'Google Safe Browsing phishing test URL'
    },
    {
        'url': 'http://www.testingmcafeesites.com/testcat_be.html',
        'expected': 'MALICIOUS',
        'description': 'McAfee malware test site'
    },
    {
        'url': 'https://testsafebrowsing.appspot.com/s/phishing.html',
        'expected': 'MALICIOUS',
        'description': 'Google Safe Browsing (HTTPS variant)'
    },
    
    # BENIGN URLS (should be BENIGN)
    {
        'url': 'https://www.google.com',
        'expected': 'BENIGN',
        'description': 'Google homepage'
    },
    {
        'url': 'https://github.com',
        'expected': 'BENIGN',
        'description': 'GitHub'
    },
]

# Run tests
print_header("RUNNING PHISHING DETECTION TESTS")

passed = 0
failed = 0
results_summary = []

for i, test_case in enumerate(test_cases, 1):
    url = test_case['url']
    expected = test_case['expected']
    description = test_case['description']
    
    print(f"\nTest {i}/{len(test_cases)}: {description}")
    
    try:
        result = engine.analyze(url, {})
        
        if print_result(url, result, expected):
            passed += 1
            results_summary.append({
                'url': url,
                'status': 'PASS',
                'classification': result['final_classification'],
                'risk_score': result['overall_risk']
            })
        else:
            failed += 1
            results_summary.append({
                'url': url,
                'status': 'FAIL',
                'classification': result['final_classification'],
                'risk_score': result['overall_risk'],
                'expected': expected
            })
    except Exception as e:
        print(f"ERROR: {str(e)}\n")
        failed += 1
        results_summary.append({
            'url': url,
            'status': 'ERROR',
            'error': str(e)
        })

# Print summary
print_header("TEST SUMMARY")

print(f"Total Tests: {len(test_cases)}")
print(f"Passed: {passed}")
print(f"Failed: {failed}")
print(f"Success Rate: {(passed/len(test_cases)*100):.1f}%\n")

print("Results by URL:")
for result in results_summary:
    status_icon = "PASS" if result['status'] == 'PASS' else "FAIL"
    if result['status'] in ['PASS', 'FAIL']:
        print(f"  [{status_icon}] {result['url']}: {result['classification']} ({result['risk_score']}/100)")
    else:
        print(f"  [ERROR] {result['url']}: ERROR")

# Overall conclusion
print(f"\n{'='*80}")
if failed == 0:
    print("SUCCESS! ALL TESTS PASSED - PHISHING DETECTION WORKING CORRECTLY!")
else:
    print(f"WARNING: {failed} TEST(S) FAILED - REVIEW RESULTS ABOVE")
print(f"{'='*80}\n")

# Export results to JSON
timestamp = datetime.now().isoformat()
export_data = {
    'timestamp': timestamp,
    'total_tests': len(test_cases),
    'passed': passed,
    'failed': failed,
    'success_rate': f"{(passed/len(test_cases)*100):.1f}%",
    'results': results_summary
}

print("Saving detailed results to test_results.json...")
with open('test_results.json', 'w') as f:
    json.dump(export_data, f, indent=2)
print("OK: Results saved\n")
