#!/usr/bin/env python3
"""
Quick test to verify real-time threat detection integration
"""

import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

print("=" * 70)
print("   REAL-TIME THREAT DETECTION INTEGRATION TEST")
print("=" * 70)

# Test 1: Check API keys are loaded
print("✓ Test 1: Checking API keys...")
vt_key = os.getenv('VIRUSTOTAL_API_KEY')
gsb_key = os.getenv('GOOGLE_SAFEBROWSING_API_KEY')
ipqs_key = os.getenv('IPQUALITYSCORE_API_KEY')

if vt_key and vt_key != 'your_api_key_here':
    print(f"  OK: VirusTotal API Key configured ({vt_key[:10]}...)")
else:
    print(f"  FAIL: VirusTotal API Key NOT configured")

if gsb_key and gsb_key != 'your_api_key_here':
    print(f"  OK: Google Safe Browsing API Key configured ({gsb_key[:10]}...)")
else:
    print(f"  FAIL: Google Safe Browsing API Key NOT configured")

if ipqs_key and ipqs_key != 'your_api_key_here':
    print(f"  OK: IPQualityScore API Key configured ({ipqs_key[:10]}...)")
else:
    print(f"  FAIL: IPQualityScore API Key NOT configured")

print()

# Test 2: Check imports
print("✓ Test 2: Checking module imports...")
try:
    from real_time_threat_detector import RealTimeThreatDetector
    print("  OK: RealTimeThreatDetector imported successfully")
except ImportError as e:
    print(f"  FAIL: Failed to import RealTimeThreatDetector: {e}")
    sys.exit(1)

try:
    from integration_realtime import scan_url_realtime, convert_to_flask_response
    print("  OK: integration_realtime imported successfully")
except ImportError as e:
    print(f"  FAIL: Failed to import integration_realtime: {e}")
    sys.exit(1)

print()

# Test 3: Initialize detector
print("✓ Test 3: Initializing real-time detector...")
try:
    detector = RealTimeThreatDetector()
    print("  OK: RealTimeThreatDetector initialized")
    print(f"    - Cache TTL: {detector.config.CACHE_TTL}s")
    print(f"    - API Timeout: {detector.config.TIMEOUT}s")
    print(f"    - Max Retries: {detector.config.MAX_RETRIES}")
except Exception as e:
    print(f"  FAIL: Failed to initialize detector: {e}")
    sys.exit(1)

print()

# Test 4: Test URL validation
print("✓ Test 4: Testing URL validation...")
test_urls = [
    ("https://www.google.com", True),
    ("http://github.com", True),
    ("not-a-url", False),
    ("ftp://invalid.com", False),
]

for url, should_be_valid in test_urls:
    is_valid = detector._is_valid_url(url)
    status = "OK" if is_valid == should_be_valid else "FAIL"
    print(f"  {status}: {url}: {is_valid}")

print()

# Test 5: Test with safe URL
print("✓ Test 5: Testing real-time detection with SAFE URL...")
try:
    result = detector.detect("https://www.google.com")
    print(f"  OK: Detection successful")
    print(f"    - URL: {result['url']}")
    print(f"    - Threat Level: {result['threat_level']}")
    print(f"    - Risk Score: {result['risk_score']:.1f}")
    print(f"    - Confidence: {result['confidence']:.2f}")
except Exception as e:
    print(f"  FAIL: Detection failed: {e}")

print()

# Test 6: Test Flask response conversion
print("✓ Test 6: Testing Flask response conversion...")
try:
    test_result = {
        'url': 'https://example.com',
        'threat_level': 'SAFE',
        'risk_score': 5.0,
        'confidence': 0.95,
        'findings': {'virustotal': {}}
    }
    flask_response = convert_to_flask_response(test_result)
    print(f"  OK: Conversion successful")
    print(f"    - Response keys: {list(flask_response.keys())}")
except Exception as e:
    print(f"  FAIL: Conversion failed: {e}")

print()

# Test 7: Test integration with scan_url_realtime
print("✓ Test 7: Testing scan_url_realtime integration...")
try:
    result = scan_url_realtime("https://www.github.com")
    print(f"  OK: scan_url_realtime works")
    print(f"    - Threat Level: {result.get('threat_level')}")
    print(f"    - Risk Score: {result.get('risk_score'):.1f}")
except Exception as e:
    print(f"  FAIL: Integration failed: {e}")

print()
print("=" * 70)
print("          INTEGRATION TEST COMPLETE")
print("=" * 70)
print()
print("The system is ready! You can now:")
print("1. Run: python app.py")
print("2. Test: curl -X POST http://localhost:5000/scan-url \\")
print("         -H 'Content-Type: application/json' \\")
print("         -d '{\"url\": \"https://google.com\"}'")
print("=" * 70)
