#!/usr/bin/env python3
"""
Debug: Check static analysis scores for all 10 URLs
"""

from security_layers.static_analysis import StaticAnalyzer

analyzer = StaticAnalyzer()

urls = [
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

print("\nSTATIC ANALYSIS SCORES:")
print("="*80)

for i, url in enumerate(urls, 1):
    result = analyzer.analyze(url, {})
    risk = result['risk_score']
    findings_count = len(result['findings'])
    print(f"{i:2}. {risk:5.1f}% | {url[:65]}")
    for finding in result['findings'][:2]:
        print(f"     -> {finding[:70]}")

print("="*80)
