"""
Real-time Integration Test
Tests Extension → Backend → Dashboard flow
"""
import requests
import time

BACKEND_URL = 'http://localhost:5000'

print("="*60)
print("🧪 REAL-TIME INTEGRATION TEST")
print("="*60)

# Test 1: Health Check
print("\n1. Testing backend health...")
try:
    response = requests.get(f'{BACKEND_URL}/health', timeout=5)
    if response.ok:
        print("   ✅ Backend is running")
    else:
        print(f"   ❌ Backend returned {response.status_code}")
        exit(1)
except Exception as e:
    print(f"   ❌ Backend not accessible: {e}")
    exit(1)

# Test 2: Simulate Extension Scan
print("\n2. Testing extension scan endpoint (/api/scan-realtime)...")
try:
    scan_data = {
        "url": "https://www.google.com",
        "page_title": "Google",
        "scripts": ["https://www.google.com/script1.js"],
        "inline_scripts": ["console.log('test');"],
        "external_resources": ["https://www.google.com/image.png"],
        "dom_structure": {"total_elements": 100, "total_scripts": 2},
        "meta_tags": {"description": "Search"},
        "forms": 1,
        "iframes": 0,
        "timestamp": int(time.time() * 1000)
    }
    
    print(f"   📤 Sending scan request for: {scan_data['url']}")
    response = requests.post(
        f'{BACKEND_URL}/api/scan-realtime',
        json=scan_data,
        headers={'X-Extension-Version': '1.0.0'},
        timeout=30
    )
    
    if response.ok:
        result = response.json()
        print(f"   ✅ Scan complete!")
        print(f"      Classification: {result.get('final_classification', 'N/A')}")
        print(f"      Risk Score: {result.get('overall_risk', 0)}%")
        print(f"      Analysis Time: {result.get('analysis_duration', 0)}s")
    else:
        print(f"   ❌ Scan failed: {response.status_code}")
        print(f"      Response: {response.text}")
        
except Exception as e:
    print(f"   ❌ Scan request failed: {e}")

# Test 3: Check Stats
print("\n3. Testing stats endpoint...")
try:
    response = requests.get(f'{BACKEND_URL}/api/scan/stats', timeout=5)
    if response.ok:
        stats = response.json()
        print(f"   ✅ Stats retrieved:")
        print(f"      Total Scans: {stats.get('total_scans', 0)}")
        print(f"      Benign: {stats.get('benign_count', 0)}")
        print(f"      Suspicious: {stats.get('suspicious_count', 0)}")
        print(f"      Malicious: {stats.get('malicious_count', 0)}")
    else:
        print(f"   ❌ Stats failed: {response.status_code}")
except Exception as e:
    print(f"   ❌ Stats request failed: {e}")

# Test 4: Check History
print("\n4. Testing history endpoint...")
try:
    response = requests.get(f'{BACKEND_URL}/api/scan/history?limit=5', timeout=5)
    if response.ok:
        history = response.json()
        scans = history.get('recent_scans', [])
        print(f"   ✅ Retrieved {len(scans)} recent scans")
        for i, scan in enumerate(scans[:3], 1):
            print(f"      {i}. {scan.get('url', 'N/A')} - {scan.get('risk_category', 'N/A')}")
    else:
        print(f"   ❌ History failed: {response.status_code}")
except Exception as e:
    print(f"   ❌ History request failed: {e}")

print("\n" + "="*60)
print("🎉 REAL-TIME INTEGRATION TEST COMPLETE")
print("="*60)
print("\n📝 Next Steps:")
print("   1. Open Chrome Extension")
print("   2. Navigate to any website")
print("   3. Check extension popup for scan results")
print("   4. Open Dashboard (http://localhost:8080)")
print("   5. Verify real-time scan appears in dashboard")
print("="*60)
