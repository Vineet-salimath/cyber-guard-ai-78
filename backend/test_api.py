import requests
import json

print("Testing backend endpoints...\n")

# Test 1: Health check
try:
    response = requests.get("http://localhost:5000/health", timeout=5)
    print(f"✅ /health - Status: {response.status_code}")
    print(f"   Response: {response.json()}\n")
except Exception as e:
    print(f"❌ /health - Error: {e}\n")

# Test 2: Scan stats
try:
    response = requests.get("http://localhost:5000/api/scan/stats", timeout=5)
    print(f"✅ /api/scan/stats - Status: {response.status_code}")
    print(f"   Response: {response.json()}\n")
except Exception as e:
    print(f"❌ /api/scan/stats - Error: {e}\n")

# Test 3: Test scan
try:
    response = requests.post(
        "http://localhost:5000/api/scan",
        headers={
            "Content-Type": "application/json",
            "Origin": "http://localhost:8082"
        },
        json={
            "url": "https://example.com",
            "timestamp": 1234567890,
            "source": "test"
        },
        timeout=10
    )
    print(f"✅ /api/scan - Status: {response.status_code}")
    print(f"   Response: {response.json()}\n")
except Exception as e:
    print(f"❌ /api/scan - Error: {e}\n")
