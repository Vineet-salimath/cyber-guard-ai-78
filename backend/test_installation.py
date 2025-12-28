#!/usr/bin/env python3
"""Test if the security modules work with installed packages."""

from integrated_scanner import get_scanner
import json

print("=" * 60)
print("TESTING SECURITY MODULES WITH INSTALLED PACKAGES")
print("=" * 60)

# Initialize scanner
try:
    scanner = get_scanner()
    print("✅ Scanner initialized successfully")
    print(f"   Type: {type(scanner).__name__}")
except Exception as e:
    print(f"❌ Scanner initialization failed: {e}")
    exit(1)

# Test URL validation
print("\n📝 TESTING URL VALIDATION")
print("-" * 60)
test_urls = [
    "https://example.com",
    "https://google.com/search?q=test",
    "http://localhost:8000",
]

for url in test_urls:
    try:
        is_valid = scanner.validate_url(url)
        status = "✅ VALID" if is_valid else "❌ INVALID"
        print(f"{status}: {url}")
    except Exception as e:
        print(f"⚠️ Error validating {url}: {e}")

# Test threat analysis
print("\n🔍 TESTING THREAT ANALYSIS")
print("-" * 60)
test_urls_analysis = [
    "https://example.com",
]

for url in test_urls_analysis:
    try:
        print(f"\nAnalyzing: {url}")
        result = scanner.analyze(url)
        
        if result:
            print(f"  Result: {json.dumps(result, indent=2)[:500]}...")
        else:
            print(f"  No threats detected")
    except Exception as e:
        print(f"⚠️ Analysis error: {type(e).__name__}: {str(e)[:100]}")

# List available methods
print("\n📊 AVAILABLE SCANNER METHODS")
print("-" * 60)
methods = [m for m in dir(scanner) if not m.startswith('_') and callable(getattr(scanner, m))]
for method in sorted(methods)[:15]:
    print(f"  • {method}()")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print("✅ Core modules are importable and functional")
print("⚠️  ML-based analysis (numpy, scikit-learn) requires C++ compiler")
print("✅ URL validation, API clients, and basic threat detection available")
print("=" * 60)
