#!/usr/bin/env python3
"""Test the phishing URL detection fix"""

from risk_engine import UnifiedRiskEngine

engine = UnifiedRiskEngine()

# Test URLs
test_urls = [
    'http://testsafebrowsing.appspot.com/s/phishing.html',
    'http://www.testingmcafeesites.com/testcat_be.html',
    'https://example.com'  # Normal URL for comparison
]

print("\n" + "="*80)
print("TESTING PHISHING URL DETECTION FIX")
print("="*80 + "\n")

for url in test_urls:
    print(f"\n🔍 Testing: {url}")
    result = engine.analyze(url, {})
    print(f"   Classification: {result['final_classification']}")
    print(f"   Overall Risk: {result['overall_risk']}/100")
    print(f"   Risk Level: {result['risk_level']}")
    print(f"   Status: {'✅ PASS' if (result['overall_risk'] >= 70 and 'phishing' in url.lower()) or (result['overall_risk'] < 40 and 'example' in url) else '❌ FAIL'}")

print("\n" + "="*80)
