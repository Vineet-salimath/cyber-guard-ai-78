# URL Scanner Routes - End-to-end threat detection pipeline
# Integrates with real-time threat detection and safe redirect system

from flask import Blueprint, request, jsonify
from urllib.parse import unquote
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Create blueprint for URL scanner routes
url_scanner_bp = Blueprint('url_scanner', __name__, url_prefix='/api/scanner')

# These will be injected by main app
url_safety_service = None
notification_service = None
risk_engine = None
socketio = None

def init_scanner_routes(app, _url_safety_service, _notification_service, _risk_engine, _socketio=None):
    """
    Initialize scanner routes with services.
    
    Call this in your main Flask app setup:
    
    from scanner_routes import init_scanner_routes
    init_scanner_routes(app, url_safety_service, notification_service, risk_engine, socketio)
    """
    global url_safety_service, notification_service, risk_engine, socketio
    url_safety_service = _url_safety_service
    notification_service = _notification_service
    risk_engine = _risk_engine
    socketio = _socketio
    
    app.register_blueprint(url_scanner_bp)

def register_socketio_handlers(_socketio):
    """
    Register Socket.io event handlers for real-time scanning.
    
    Call this after initializing socketio:
    
    register_socketio_handlers(socketio)
    """
    global socketio
    socketio = _socketio
    
    if not socketio:
        return
    
    @socketio.on('connect')
    def on_connect():
        logger.info(f"Scanner client connected: {request.sid}")
    
    @socketio.on('disconnect')
    def on_disconnect():
        logger.info(f"Scanner client disconnected: {request.sid}")
    
    @socketio.on('scan_url')
    def on_scan_url(data):
        """Handle real-time URL scan request via Socket.io."""
        url = data.get('url')
        user_id = data.get('user_id')
        
        if not url:
            socketio.emit('scan_error', {'error': 'URL required'})
            return
        
        try:
            # Perform URL check
            result = url_safety_service.check_url_safety(url, user_id)
            
            # Emit result back to client
            socketio.emit('scan_result', {
                'url': url,
                'verdict': result['verdict'],
                'action': result['action'],
                'reason': result['reason'],
                'risk_score': result['risk_score'],
                'engine_detection_count': result['engine_detection_count'],
                'engine_total_count': result['engine_total_count'],
                'threat_types': result['threat_types'],
                'scan_id': result['scan_id']
            })
            
            logger.info(f"[Socket.io] Scanned {url} for user {user_id}: {result['verdict']}")
        except Exception as e:
            logger.error(f"Socket.io scan error: {e}")
            socketio.emit('scan_error', {'error': str(e)})

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINT: /api/scanner/submit-url (Main scanning endpoint)
# ═══════════════════════════════════════════════════════════════════════════

@url_scanner_bp.route('/submit-url', methods=['POST', 'GET'])
def submit_url_for_scanning():
    """
    Main URL scanning endpoint for extension and frontend integration.
    
    POST /api/scanner/submit-url
    Content-Type: application/json
    
    Request Body:
        {
            "target_url": "https://example.com",
            "user_id": "user123",
            "source": "extension|web|api"  (optional)
        }
    
    GET /api/scanner/submit-url?url=<encodedUrl>&user_id=user123
    
    Response:
        {
            "success": true,
            "verdict": "clean|malicious|suspicious",
            "action": "allowed|blocked|warned",
            "risk_score": 0-100,
            "engine_detection_count": 45,
            "engine_total_count": 60,
            "threat_types": ["MALWARE", "PHISHING"],
            "scan_id": 123,
            "message": "URL scanned successfully"
        }
    """
    
    # Get URL from request (POST or GET)
    if request.method == 'POST':
        data = request.get_json() or {}
        target_url = data.get('target_url')
        user_id = data.get('user_id')
        source = data.get('source', 'api')
    else:  # GET
        target_url = request.args.get('url')
        user_id = request.args.get('user_id')
        source = request.args.get('source', 'web')
        
        # URL decode if needed
        if target_url:
            try:
                target_url = unquote(target_url)
            except:
                pass
    
    if not target_url:
        return jsonify({
            'success': False,
            'error': 'Missing target_url or url parameter',
            'message': 'URL is required for scanning'
        }), 400
    
    try:
        # Perform URL safety check
        result = url_safety_service.check_url_safety(target_url, user_id)
        
        logger.info(f"[{source.upper()}] URL scanned: {target_url}")
        logger.info(f"  Verdict: {result['verdict']} | Risk: {result['risk_score']}")
        
        return jsonify({
            'success': True,
            'verdict': result['verdict'],
            'action': result['action'],
            'reason': result['reason'],
            'risk_score': result['risk_score'],
            'engine_detection_count': result['engine_detection_count'],
            'engine_total_count': result['engine_total_count'],
            'threat_types': result['threat_types'],
            'scan_id': result['scan_id'],
            'message': f"URL classified as {result['verdict'].upper()}"
        }), 200
    
    except Exception as e:
        logger.error(f"Scanner error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Error scanning URL'
        }), 500

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINT: /api/scanner/batch-scan (Batch URL scanning)
# ═══════════════════════════════════════════════════════════════════════════

@url_scanner_bp.route('/batch-scan', methods=['POST'])
def batch_scan_urls():
    """
    Scan multiple URLs in a single request.
    
    POST /api/scanner/batch-scan
    Content-Type: application/json
    
    Request Body:
        {
            "urls": ["https://url1.com", "https://url2.com"],
            "user_id": "user123"
        }
    
    Response:
        {
            "success": true,
            "results": [
                {
                    "url": "https://url1.com",
                    "verdict": "clean",
                    "risk_score": 0,
                    ...
                },
                ...
            ],
            "summary": {
                "total": 2,
                "clean": 1,
                "suspicious": 0,
                "malicious": 1
            }
        }
    """
    data = request.get_json() or {}
    urls = data.get('urls', [])
    user_id = data.get('user_id')
    
    if not urls or not isinstance(urls, list):
        return jsonify({'error': 'URLs list required'}), 400
    
    if len(urls) > 100:
        return jsonify({'error': 'Maximum 100 URLs per request'}), 400
    
    results = []
    summary = {'total': len(urls), 'clean': 0, 'suspicious': 0, 'malicious': 0}
    
    try:
        for url in urls:
            result = url_safety_service.check_url_safety(url, user_id)
            
            results.append({
                'url': url,
                'verdict': result['verdict'],
                'action': result['action'],
                'risk_score': result['risk_score'],
                'engine_detection_count': result['engine_detection_count'],
                'engine_total_count': result['engine_total_count'],
                'scan_id': result['scan_id']
            })
            
            # Update summary
            summary[result['verdict']] += 1
        
        logger.info(f"Batch scan completed: {len(urls)} URLs | User: {user_id}")
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': summary
        }), 200
    
    except Exception as e:
        logger.error(f"Batch scan error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINT: /api/scanner/quick-check (Ultra-fast basic check)
# ═══════════════════════════════════════════════════════════════════════════

@url_scanner_bp.route('/quick-check', methods=['POST'])
def quick_check():
    """
    Ultra-fast URL check without threat intelligence (local lists only).
    
    POST /api/scanner/quick-check
    Content-Type: application/json
    
    Request Body:
        {
            "target_url": "https://example.com"
        }
    
    Response:
        {
            "verdict": "clean|malicious",
            "action": "allowed|blocked",
            "reason": "blacklist_match|allowlist_match|unknown"
        }
    """
    data = request.get_json() or {}
    target_url = data.get('target_url')
    
    if not target_url:
        return jsonify({'error': 'target_url required'}), 400
    
    try:
        # Check only local lists (fast)
        verdict, reason = url_safety_service.check_local_lists(target_url)
        
        if verdict:
            action = 'blocked' if verdict == 'malicious' else 'allowed'
            return jsonify({
                'verdict': verdict,
                'action': action,
                'reason': reason
            }), 200
        else:
            # Unknown - return safe by default
            return jsonify({
                'verdict': 'clean',
                'action': 'allowed',
                'reason': 'unknown'
            }), 200
    
    except Exception as e:
        logger.error(f"Quick check error: {e}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINT: /api/scanner/stats (Get scanning statistics)
# ═══════════════════════════════════════════════════════════════════════════

@url_scanner_bp.route('/stats', methods=['GET'])
def get_scanner_stats():
    """
    Get URL scanning statistics.
    
    GET /api/scanner/stats?user_id=user123&period=day
    
    Query Parameters:
        user_id: (optional) User ID for personal stats
        period: day|week|month (default: day)
    
    Response:
        {
            "period": "day",
            "total_scans": 150,
            "clean_urls": 140,
            "suspicious_urls": 5,
            "malicious_urls": 5,
            "avg_risk_score": 8.5,
            "top_threats": ["MALWARE", "PHISHING"]
        }
    """
    user_id = request.args.get('user_id')
    
    try:
        if user_id:
            # Get user's scan stats
            scans = url_safety_service.get_user_scan_history(user_id, limit=1000)
        else:
            # Get all scan stats (admin)
            scans = url_safety_service.get_all_blocked_urls(limit=1000)
        
        if not scans:
            return jsonify({
                'total_scans': 0,
                'clean_urls': 0,
                'suspicious_urls': 0,
                'malicious_urls': 0,
                'avg_risk_score': 0,
                'top_threats': []
            }), 200
        
        # Calculate stats
        stats = {
            'total_scans': len(scans),
            'clean_urls': sum(1 for s in scans if s.get('verdict') == 'clean'),
            'suspicious_urls': sum(1 for s in scans if s.get('verdict') == 'suspicious'),
            'malicious_urls': sum(1 for s in scans if s.get('verdict') == 'malicious'),
            'avg_risk_score': sum(s.get('risk_score', 0) for s in scans) / len(scans) if scans else 0
        }
        
        return jsonify(stats), 200
    
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'error': str(e)}), 500

# ═══════════════════════════════════════════════════════════════════════════
# HEALTH CHECK ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════

@url_scanner_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for scanner service.
    
    GET /api/scanner/health
    
    Response:
        {
            "status": "healthy",
            "service": "url_scanner",
            "threat_intelligence": "connected",
            "database": "connected"
        }
    """
    status = {
        'status': 'healthy',
        'service': 'url_scanner',
        'threat_intelligence': 'connected' if url_safety_service else 'disconnected',
        'database': 'connected' if url_safety_service else 'disconnected'
    }
    
    return jsonify(status), 200
