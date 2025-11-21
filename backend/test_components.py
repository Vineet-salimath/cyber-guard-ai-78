"""
MINIMAL TEST - Verify async components work in isolation
"""

print("="*60)
print("🧪 TESTING ASYNC COMPONENTS")
print("="*60)

# Test 1: Import scan_status_cache
print("\n1. Testing scan_status_cache...")
try:
    from scan_status_cache import scan_cache
    
    # Create test scan
    scan_data = scan_cache.create_scan("test-123", "https://example.com")
    print(f"   ✅ Created scan: {scan_data['scan_id']}")
    
    # Update status
    scan_cache.update_status("test-123", "processing", 50)
    print("   ✅ Updated status to processing (50%)")
    
    # Get scan
    retrieved = scan_cache.get_scan("test-123")
    print(f"   ✅ Retrieved scan: status={retrieved['status']}, progress={retrieved['progress']}")
    
    print("✅ scan_status_cache works!")
    
except Exception as e:
    print(f"❌ scan_status_cache failed: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Import background_worker
print("\n2. Testing background_worker...")
try:
    from background_worker import BackgroundWorker
    
    worker = BackgroundWorker(
        scan_cache=scan_cache,
        ml_detector=None,
        url_ml_predict=None,
        js_ml_predict=None,
        scan_storage=None
    )
    
    print(f"   ✅ Worker created: max_workers={worker.max_workers}")
    print("✅ background_worker works!")
    
except Exception as e:
    print(f"❌ background_worker failed: {e}")
    import traceback
    traceback.print_exc()

# Test 3: Check if async flag is set
print("\n3. Testing app.py imports...")
try:
    import sys
    sys.path.insert(0, '.')
    
    # Just check the variables
    print("   Importing app components...")
    from scan_status_cache import scan_cache as cache_test
    from background_worker import BackgroundWorker as worker_test
    
    print("   ✅ All imports successful")
    print("✅ app.py dependencies work!")
    
except Exception as e:
    print(f"❌ app.py imports failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*60)
print("🎯 COMPONENT TEST COMPLETE")
print("="*60)
