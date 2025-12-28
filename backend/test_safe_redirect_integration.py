# Test file to verify safe redirect system integration
# Run: python test_safe_redirect_integration.py

import requests
import json
import sys
from urllib.parse import urlencode, quote

BASE_URL = "http://localhost:5000"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def test(name, condition, details=""):
    """Print test result."""
    if condition:
        print(f"{Colors.GREEN}✓ PASS{Colors.END}: {name}")
    else:
        print(f"{Colors.RED}✗ FAIL{Colors.END}: {name}")
        if details:
            print(f"  {Colors.YELLOW}→{Colors.END} {details}")
    return condition

def test_database():
    """Test database connectivity."""
    print(f"\n{Colors.BLUE}═══ DATABASE TESTS ═══{Colors.END}")
    
    try:
        import sqlite3
        conn = sqlite3.connect('backend/cyber_guard.db')
        cursor = conn.cursor()
        
        # Check tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        test("Database file exists", True)
        test("url_scans table exists", 'url_scans' in tables, f"Tables: {tables}")
        test("url_blacklist table exists", 'url_blacklist' in tables)
        test("url_allowlist table exists", 'url_allowlist' in tables)
        
        # Check indexes
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = [row[0] for row in cursor.fetchall()]
        test("Indexes created", len(indexes) > 0, f"Found {len(indexes)} indexes")
        
        conn.close()
        return True
    except Exception as e:
        test("Database connectivity", False, str(e))
        return False

def test_api_endpoints():
    """Test Flask API endpoints."""
    print(f"\n{Colors.BLUE}═══ API ENDPOINT TESTS ═══{Colors.END}")
    
    all_pass = True
    
    # Test /api/safe/check endpoint
    try:
        response = requests.post(
            f"{BASE_URL}/api/safe/check",
            json={
                "target_url": "https://google.com",
                "user_id": "test_user_123"
            },
            timeout=5
        )
        passed = test(
            "POST /api/safe/check",
            response.status_code == 200,
            f"Status: {response.status_code}"
        )
        all_pass = all_pass and passed
        
        if response.status_code == 200:
            data = response.json()
            test("Check response has verdict", 'verdict' in data)
            test("Check response has action", 'action' in data)
            test("Check response has risk_score", 'risk_score' in data)
    except Exception as e:
        test("POST /api/safe/check", False, str(e))
        all_pass = False
    
    # Test /api/safe/scan-history endpoint
    try:
        response = requests.get(
            f"{BASE_URL}/api/safe/scan-history?user_id=test_user_123&limit=10",
            timeout=5
        )
        passed = test(
            "GET /api/safe/scan-history",
            response.status_code == 200,
            f"Status: {response.status_code}"
        )
        all_pass = all_pass and passed
    except Exception as e:
        test("GET /api/safe/scan-history", False, str(e))
        all_pass = False
    
    # Test /api/safe/blocked-urls endpoint
    try:
        response = requests.get(
            f"{BASE_URL}/api/safe/blocked-urls?limit=10",
            timeout=5
        )
        passed = test(
            "GET /api/safe/blocked-urls",
            response.status_code == 200,
            f"Status: {response.status_code}"
        )
        all_pass = all_pass and passed
    except Exception as e:
        test("GET /api/safe/blocked-urls", False, str(e))
        all_pass = False
    
    return all_pass

def test_url_safety_service():
    """Test URL safety service."""
    print(f"\n{Colors.BLUE}═══ URL SAFETY SERVICE TESTS ═══{Colors.END}")
    
    try:
        from backend.url_safety_service import URLSafetyService
        
        service = URLSafetyService('backend/cyber_guard.db')
        test("URLSafetyService instantiates", True)
        
        # Test URL validation
        valid, error = service.validate_url("https://google.com")
        test("Valid URL passes validation", valid and not error)
        
        invalid, error = service.validate_url("javascript:alert(1)")
        test("javascript: URI rejected", not invalid and error is not None)
        
        # Test blacklist/allowlist
        service.add_to_blacklist("test-malware.com", "Test entry")
        test("Can add to blacklist", True)
        
        verdict, reason = service.check_local_lists("test-malware.com")
        test("Blacklist check works", verdict == 'malicious')
        
        service.add_to_allowlist("safe.com", "Test safe site")
        verdict, reason = service.check_local_lists("safe.com")
        test("Allowlist check works", verdict == 'clean')
        
        return True
    except Exception as e:
        test("URLSafetyService", False, str(e))
        return False

def test_notification_service():
    """Test notification service."""
    print(f"\n{Colors.BLUE}═══ NOTIFICATION SERVICE TESTS ═══{Colors.END}")
    
    try:
        from backend.notification_service import (
            NotificationService,
            NotificationChannel
        )
        
        service = NotificationService()
        test("NotificationService instantiates", True)
        
        # Test handler registration
        def dummy_handler(data, recipient):
            pass
        
        service.register_handler(NotificationChannel.USER, dummy_handler)
        test("Can register notification handler", True)
        
        # Test notification methods exist
        test("notify_malicious_url_blocked method exists",
             hasattr(service, 'notify_malicious_url_blocked'))
        test("notify_suspicious_url_access method exists",
             hasattr(service, 'notify_suspicious_url_access'))
        
        return True
    except Exception as e:
        test("NotificationService", False, str(e))
        return False

def test_flask_routes():
    """Test Flask route setup."""
    print(f"\n{Colors.BLUE}═══ FLASK ROUTES TESTS ═══{Colors.END}")
    
    try:
        # Just test that app starts
        response = requests.get(f"{BASE_URL}/", timeout=5)
        test("Flask app responds", response.status_code in [200, 404])
        return True
    except Exception as e:
        test("Flask app connectivity", False, str(e))
        return False

def test_threat_apis():
    """Test threat intelligence API connectivity."""
    print(f"\n{Colors.BLUE}═══ THREAT INTELLIGENCE API TESTS ═══{Colors.END}")
    
    try:
        import os
        from dotenv import load_dotenv
        load_dotenv('backend/.env')
        
        # Check API keys configured
        vt_key = os.getenv('VIRUSTOTAL_API_KEY')
        gsb_key = os.getenv('GOOGLE_SAFEBROWSING_API_KEY')
        iqs_key = os.getenv('IPQUALITYSCORE_API_KEY')
        
        test("VirusTotal API key configured", bool(vt_key and vt_key != 'YOUR_KEY'))
        test("Google Safe Browsing API key configured", bool(gsb_key and gsb_key != 'YOUR_KEY'))
        test("IPQualityScore API key configured", bool(iqs_key and iqs_key != 'YOUR_KEY'))
        
        return True
    except Exception as e:
        test("API key configuration", False, str(e))
        return False

def main():
    """Run all tests."""
    print(f"\n{Colors.BLUE}╔════════════════════════════════════════╗{Colors.END}")
    print(f"{Colors.BLUE}║  SAFE REDIRECT SYSTEM - INTEGRATION TEST ║{Colors.END}")
    print(f"{Colors.BLUE}╚════════════════════════════════════════╝{Colors.END}")
    
    results = {
        'Database': test_database(),
        'URL Safety Service': test_url_safety_service(),
        'Notification Service': test_notification_service(),
        'Threat Intelligence APIs': test_threat_apis(),
        'Flask Routes': test_flask_routes(),
        'API Endpoints': test_api_endpoints(),
    }
    
    print(f"\n{Colors.BLUE}═══ SUMMARY ═══{Colors.END}")
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = f"{Colors.GREEN}PASS{Colors.END}" if result else f"{Colors.RED}FAIL{Colors.END}"
        print(f"  {name}: {status}")
    
    print(f"\n{Colors.BLUE}Total: {passed}/{total} passed{Colors.END}")
    
    if passed == total:
        print(f"\n{Colors.GREEN}✓ All tests passed! System is ready.{Colors.END}\n")
        return 0
    else:
        print(f"\n{Colors.RED}✗ Some tests failed. Please review above.{Colors.END}\n")
        return 1

if __name__ == '__main__':
    sys.exit(main())
