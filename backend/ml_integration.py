# ENHANCED BACKEND WITH ML INTEGRATION AND WEBSOCKET SUPPORT
# Add this to your existing Flask app.py

import subprocess
import json
import asyncio
import threading
from functools import wraps

# ML Integration Functions
def call_ml_service(url):
    """
    Call Python ML service to analyze URL
    
    Returns:
        dict: ML prediction results with confidence scores
    """
    try:
        print(f"🤖 Calling ML service for URL: {url}")
        
        # Call ML service
        result = subprocess.run(
            ['python', 'ml/ml_service.py', 'analyze_url', url],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=os.path.dirname(__file__)
        )
        
        if result.returncode == 0:
            ml_result = json.loads(result.stdout)
            print(f"✅ ML prediction: {ml_result.get('prediction')} ({ml_result.get('confidence')}% confidence)")
            return ml_result
        else:
            print(f"❌ ML service error: {result.stderr}")
            return {
                'error': 'ML service failed',
                'prediction': 'UNKNOWN',
                'confidence': 0,
                'risk_score': 50
            }
            
    except subprocess.TimeoutExpired:
        print("⏱️ ML service timeout")
        return {'error': 'Timeout', 'prediction': 'UNKNOWN', 'risk_score': 50}
    except Exception as e:
        print(f"❌ ML service exception: {e}")
        return {'error': str(e), 'prediction': 'UNKNOWN', 'risk_score': 50}


def calculate_hybrid_risk_score(ml_score, vt_score, threat_level):
    """
    Calculate hybrid risk score combining ML and VirusTotal results
    
    Weights:
    - ML: 40%
    - VirusTotal: 35%
    - Threat Level: 25%
    
    Args:
        ml_score: ML risk score (0-100)
        vt_score: VirusTotal risk score (0-100)
        threat_level: SAFE/SUSPICIOUS/MALICIOUS
    
    Returns:
        float: Hybrid risk score (0-100)
    """
    # Convert threat level to score
    threat_scores = {
        'SAFE': 0,
        'SUSPICIOUS': 50,
        'MALICIOUS': 100
    }
    threat_score = threat_scores.get(threat_level, 50)
    
    # Weighted average
    hybrid_score = (
        ml_score * 0.40 +
        vt_score * 0.35 +
        threat_score * 0.25
    )
    
    return round(hybrid_score, 2)


def assign_risk_level(score):
    """
    Assign risk level based on score
    
    Levels:
    - CRITICAL: 80+
    - HIGH: 60-79
    - MEDIUM: 40-59
    - LOW: 20-39
    - SAFE: <20
    """
    if score >= 80:
        return 'CRITICAL'
    elif score >= 60:
        return 'HIGH'
    elif score >= 40:
        return 'MEDIUM'
    elif score >= 20:
        return 'LOW'
    else:
        return 'SAFE'


# WebSocket broadcasting helper
def broadcast_to_websocket(data):
    """
    Broadcast data to WebSocket clients
    This runs in a separate thread to avoid blocking Flask
    """
    try:
        # Import websocket server module
        import sys
        sys.path.append(os.path.dirname(__file__))
        
        # Start event loop in thread if needed
        def run_broadcast():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                # Import and call broadcast function
                from websocket_server import broadcast_scan_result
                loop.run_until_complete(broadcast_scan_result(data))
            except Exception as e:
                print(f"❌ WebSocket broadcast error: {e}")
        
        # Run in background thread
        thread = threading.Thread(target=run_broadcast, daemon=True)
        thread.start()
        
    except Exception as e:
        print(f"⚠️ Could not broadcast to WebSocket: {e}")


# ADD THIS NEW ENDPOINT TO YOUR app.py

"""
@app.route('/api/scan/hybrid', methods=['POST'])
def hybrid_scan():
    '''
    Hybrid scan endpoint - combines ML + VirusTotal
    
    Request body:
    {
        "url": "https://example.com",
        "useML": true,
        "useAPI": true
    }
    
    Response:
    {
        "url": "https://example.com",
        "hybrid_risk_score": 45.5,
        "risk_level": "MEDIUM",
        "ml_analysis": {...},
        "virustotal_analysis": {...},
        "scan_date": "2024-11-05T10:30:00Z"
    }
    '''
    try:
        data = request.get_json()
        url_to_scan = data.get('url')
        use_ml = data.get('useML', True)
        use_api = data.get('useAPI', True)
        
        if not url_to_scan:
            return jsonify({'error': 'URL is required'}), 400
        
        print(f"🔬 Starting hybrid scan for: {url_to_scan}")
        print(f"   ML: {use_ml}, API: {use_api}")
        
        result = {
            'url': url_to_scan,
            'scan_date': datetime.now().isoformat(),
            'scan_id': hashlib.md5(url_to_scan.encode()).hexdigest()[:16]
        }
        
        # ML Analysis
        ml_score = 0
        if use_ml:
            ml_result = call_ml_service(url_to_scan)
            result['ml_analysis'] = ml_result
            ml_score = ml_result.get('risk_score', 0)
        else:
            result['ml_analysis'] = {'skipped': True}
        
        # VirusTotal Analysis
        vt_score = 0
        if use_api:
            vt_result = scan_with_virustotal(url_to_scan)
            result['virustotal_analysis'] = vt_result
            vt_score = vt_result.get('overall_risk_score', 0)
            threat_level = vt_result.get('threat_level', 'SAFE')
        else:
            result['virustotal_analysis'] = {'skipped': True}
            threat_level = 'SAFE'
        
        # Calculate hybrid score
        hybrid_score = calculate_hybrid_risk_score(ml_score, vt_score, threat_level)
        risk_level = assign_risk_level(hybrid_score)
        
        result['hybrid_risk_score'] = hybrid_score
        result['risk_level'] = risk_level
        result['threat_level'] = threat_level
        
        # Broadcast to WebSocket clients
        broadcast_to_websocket(result)
        
        # Save to database
        scan_history_db.append(result)
        
        print(f"✅ Hybrid scan complete: {risk_level} (Score: {hybrid_score})")
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Error in hybrid scan: {str(e)}")
        return jsonify({
            'error': str(e),
            'url': url_to_scan if 'url_to_scan' in locals() else 'unknown'
        }), 500
"""

print("""
╔════════════════════════════════════════════════════════════════╗
║  ML INTEGRATION MODULE FOR MALWARESNIPPER                      ║
║  Add the functions above to your backend/app.py                ║
║                                                                 ║
║  New Features:                                                  ║
║  - ML-based URL analysis                                        ║
║  - Hybrid risk scoring (ML + VirusTotal)                        ║
║  - WebSocket broadcasting                                       ║
║  - /api/scan/hybrid endpoint                                    ║
╚════════════════════════════════════════════════════════════════╝
""")
