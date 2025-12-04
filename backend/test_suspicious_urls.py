#!/usr/bin/env python3
"""
Test 10 Suspicious URLs (Expected Risk: 40-70% / SUSPICIOUS)
"""

from risk_engine import UnifiedRiskEngine

engine = UnifiedRiskEngine()

suspicious_urls = [
    "http://secure-login-update-check.com/account/verify",
    "http://banking-authentication-alert.net/login/confirm",
    "https://paytm-security-check.in/verify-user-session",
    "http://paypal-update-info-support.com/login/secure",
    "https://microsoft-recovery-alert.support-session.com/reset-password",
    "http://verify-id-protect-security.org/confirm-details",
    "http://amazon-order-problem-resolve.info/login",
    "https://account-check-validation-service.net/secure",
    "http://appleid-security-warning-help.com/verify",
    "http://insta-support-verify-form-login.xyz/auth"
]

print("\n" + "="*80)
print("TESTING 10 SUSPICIOUS URLs (Expected: 40-70% SUSPICIOUS)")
print("="*80 + "\n")

results = []
passed = 0
failed = 0

for i, url in enumerate(suspicious_urls, 1):
    print(f"Test {i}/10: {url[:60]}...")
    
    try:
        result = engine.analyze(url, {})
        risk_score = result['overall_risk']
        classification = result['final_classification']
        
        # Check if score is in suspicious range (40-70)
        is_suspicious = 40 <= risk_score < 70
        is_correct_class = classification == 'SUSPICIOUS'
        
        status = "PASS" if (is_suspicious and is_correct_class) else "FAIL"
        
        if status == "PASS":
            passed += 1
        else:
            failed += 1
        
        results.append({
            'url': url,
            'risk_score': risk_score,
            'classification': classification,
            'status': status
        })
        
        print(f"   Risk: {risk_score}/100 | Classification: {classification} | [{status}]\n")
        
    except Exception as e:
        print(f"   ERROR: {str(e)}\n")
        failed += 1
        results.append({
            'url': url,
            'status': 'ERROR',
            'error': str(e)
        })

# Summary
print("="*80)
print("SUMMARY")
print("="*80)
print(f"Total Tests: {len(suspicious_urls)}")
print(f"Passed: {passed}")
print(f"Failed: {failed}")
print(f"Success Rate: {(passed/len(suspicious_urls)*100):.1f}%\n")

print("RESULTS BY URL:")
for result in results:
    if result['status'] in ['PASS', 'FAIL']:
        status = result['status']
        risk = result['risk_score']
        classification = result['classification']
        print(f"  [{status}] {risk:5.1f}% | {classification:10} | {result['url'][:55]}")
    else:
        print(f"  [ERROR] {result['url']}")

print("\n" + "="*80)
if failed == 0:
    print("SUCCESS: All 10 suspicious URLs correctly classified!")
else:
    print(f"WARNING: {failed} URL(s) not in expected range")
print("="*80 + "\n")
