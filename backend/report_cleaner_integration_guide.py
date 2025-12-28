#!/usr/bin/env python3
"""
Report Cleaner Integration Guide
Quick reference for integrating automated report cleaning into your application
"""

# ============================================================================
# INTEGRATION METHOD 1: Rule-Based Cleaning (No API Keys Required)
# ============================================================================

def method1_rule_based():
    """
    Simplest approach: Uses regex patterns and rules, no external API calls.
    Perfect for: Batch processing, offline use, no LLM costs
    """
    from report_cleaner import ReportCleaner
    
    cleaner = ReportCleaner()
    
    raw_report = """
    Report ID: Ø=scan_001 Date: 2024-01-15
    URL: https://example.com/malwareþfile
    
    Detections: 8/67 þ detected
    Kaspersky | detected | Trojan.Win32.XYZ
    Norton | clear | Safe
    """
    
    # Process the report
    cleaned_data = cleaner.process_report(raw_report)
    
    # Get structured data
    print("Threat Level:", cleaned_data['threat_level'])
    print("Detection Rate:", cleaned_data['detection_rate'])
    print("URLs:", cleaned_data['urls'])
    
    # Get formatted markdown
    markdown_report = cleaner.format_as_markdown(cleaned_data)
    print("\nFormatted Report:\n", markdown_report)
    
    return cleaned_data


# ============================================================================
# INTEGRATION METHOD 2: LLM-Based Cleaning with Fallback
# ============================================================================

def method2_llm_based():
    """
    Advanced approach: Uses LLM API when available, falls back to rule-based.
    Perfect for: Professional formatting, enterprise use, better accuracy
    Requirements: OpenAI API key OR Anthropic API key (optional)
    """
    from llm_report_integration import HybridReportCleaner, get_llm_provider
    
    # Initialize with automatic LLM detection
    llm_provider = get_llm_provider('auto')  # Tries OpenAI, then Anthropic
    cleaner = HybridReportCleaner(llm_provider=llm_provider)
    
    raw_report = "... your raw malware sniffer report ..."
    
    # Clean with LLM if available, fallback to rules
    result = cleaner.clean_report(raw_report, use_llm=True)
    
    print(f"Cleaning Method: {result['method']}")
    print(f"Success: {result['success']}")
    print(f"Cleaned Report:\n{result['cleaned_report']}")
    
    return result


# ============================================================================
# INTEGRATION METHOD 3: In Scanner Routes (Flask)
# ============================================================================

def method3_flask_integration():
    """
    Add report cleaning to your existing Flask scanner routes.
    """
    from flask import Blueprint, request, jsonify
    from llm_report_integration import HybridReportCleaner, get_llm_provider
    import logging
    
    logger = logging.getLogger(__name__)
    
    # Initialize cleaner once at startup
    llm_provider = get_llm_provider('auto')
    report_cleaner = HybridReportCleaner(llm_provider=llm_provider)
    
    # Create a new route for report cleaning
    clean_report_bp = Blueprint('report_cleaning', __name__, url_prefix='/api/reports')
    
    @clean_report_bp.route('/clean', methods=['POST'])
    def clean_report_endpoint():
        """
        POST /api/reports/clean
        
        Request body:
        {
            "raw_report": "...",  # Raw malware report text
            "use_llm": true        # Optional, default true
        }
        
        Response:
        {
            "success": true,
            "method": "LLM-based (with rule-based fallback)",
            "cleaned_report": "...",  # Clean markdown
            "structured_data": {...},  # Extracted threat data
            "timestamp": "2024-01-15T10:30:00Z"
        }
        """
        try:
            data = request.get_json()
            raw_report = data.get('raw_report')
            use_llm = data.get('use_llm', True)
            
            if not raw_report:
                return jsonify({'error': 'raw_report required'}), 400
            
            # Clean the report
            result = report_cleaner.clean_report(raw_report, use_llm=use_llm)
            
            # Add timestamp
            from datetime import datetime
            result['timestamp'] = datetime.utcnow().isoformat() + 'Z'
            
            return jsonify(result), 200 if result['success'] else 400
            
        except Exception as e:
            logger.error(f"Error in clean_report_endpoint: {e}")
            return jsonify({'error': str(e), 'success': False}), 500
    
    return clean_report_bp


# ============================================================================
# INTEGRATION METHOD 4: Async Processing (Background Jobs)
# ============================================================================

def method4_async_cleaning():
    """
    Process reports asynchronously using your existing async infrastructure.
    Good for: Batch processing, large reports, non-blocking operations
    """
    from llm_report_integration import HybridReportCleaner, get_llm_provider
    from datetime import datetime
    import json
    
    async def clean_report_async(raw_report: str, report_id: str = None):
        """
        Async function to clean a report.
        
        Usage with asyncio:
            result = await clean_report_async(raw_report)
        
        Usage with your async task queue (Celery, etc.):
            clean_report_task.apply_async(args=[raw_report])
        """
        cleaner = HybridReportCleaner(llm_provider=get_llm_provider('auto'))
        
        result = cleaner.clean_report(raw_report)
        
        # Save to database or storage
        report_record = {
            'id': report_id,
            'timestamp': datetime.utcnow().isoformat(),
            'method': result['method'],
            'cleaned_report': result['cleaned_report'],
            'structured_data': result['structured_data'],
            'success': result['success']
        }
        
        # Example: Save to file
        if report_id:
            with open(f'reports/{report_id}_cleaned.json', 'w') as f:
                json.dump(report_record, f, indent=2)
        
        return report_record
    
    return clean_report_async


# ============================================================================
# INTEGRATION METHOD 5: Real-Time Threat Updates (WebSocket)
# ============================================================================

def method5_websocket_integration():
    """
    Stream cleaned report data to clients in real-time via WebSocket.
    """
    from llm_report_integration import HybridReportCleaner, get_llm_provider
    import json
    
    # Initialize cleaner
    cleaner = HybridReportCleaner(llm_provider=get_llm_provider('auto'))
    
    def emit_cleaned_report(socketio, room, raw_report):
        """
        Clean a report and emit updates via WebSocket.
        
        Usage in your WebSocket handler:
            emit_cleaned_report(socketio, request.sid, raw_report)
        """
        # Start processing
        socketio.emit('report_processing', {
            'status': 'Processing raw report...',
            'progress': 10
        }, room=room)
        
        # Clean the report
        result = cleaner.clean_report(raw_report)
        
        # Stream completed report
        socketio.emit('report_cleaned', {
            'status': 'Report cleaned successfully',
            'progress': 100,
            'method': result['method'],
            'cleaned_report': result['cleaned_report'],
            'threat_level': result['structured_data'].get('threat_level'),
            'detection_rate': result['structured_data'].get('detection_rate'),
            'recommendations': result['structured_data'].get('recommendations')
        }, room=room)
    
    return emit_cleaned_report


# ============================================================================
# SETUP INSTRUCTIONS
# ============================================================================

def setup_instructions():
    """
    Complete setup instructions for report cleaning integration.
    """
    return """
    REPORT CLEANER SETUP GUIDE
    ==========================
    
    1. INSTALL DEPENDENCIES
       ========================
       
       For rule-based cleaning only:
       - No additional dependencies required!
       
       For LLM-based cleaning (optional):
       
       OpenAI API:
       $ pip install openai
       $ export OPENAI_API_KEY="your-api-key-here"
       
       Anthropic Claude API:
       $ pip install anthropic
       $ export ANTHROPIC_API_KEY="your-api-key-here"
    
    
    2. BASIC USAGE
       ========================
       
       from report_cleaner import ReportCleaner
       
       cleaner = ReportCleaner()
       cleaned = cleaner.process_report(raw_report)
       markdown = cleaner.format_as_markdown(cleaned)
    
    
    3. WITH LLM INTEGRATION
       ========================
       
       from llm_report_integration import HybridReportCleaner, get_llm_provider
       
       llm = get_llm_provider('auto')  # Auto-detects available API
       cleaner = HybridReportCleaner(llm_provider=llm)
       result = cleaner.clean_report(raw_report)
    
    
    4. IN YOUR FLASK APP
       ========================
       
       # In your main app initialization:
       from llm_report_integration import HybridReportCleaner, get_llm_provider
       
       app.report_cleaner = HybridReportCleaner(
           llm_provider=get_llm_provider('auto')
       )
       
       # In your route:
       @app.route('/api/reports/clean', methods=['POST'])
       def clean_report():
           raw = request.json['raw_report']
           result = app.report_cleaner.clean_report(raw)
           return jsonify(result)
    
    
    5. FEATURES
       ========================
       
       ✅ Removes encoding artifacts (Ø=, þ, ÿ, ™, etc.)
       ✅ Normalizes detection statuses
       ✅ Classifies threat levels (SAFE to CRITICAL)
       ✅ Extracts URLs, dates, report IDs
       ✅ Generates actionable recommendations
       ✅ Formats as professional markdown
       ✅ Falls back gracefully if LLM unavailable
       ✅ No external dependencies for core functionality
    
    
    6. QUALITY CHECKS
       ========================
       
       The cleaner verifies:
       - All junk characters removed
       - Proper table formatting
       - URLs properly formatted
       - Dates in standard format
       - Report IDs identified
       - Status values normalized
       - No fabricated data
    
    
    7. COST CONSIDERATIONS
       ========================
       
       Rule-based cleaning: FREE (no API calls)
       
       LLM-based cleaning:
       - OpenAI: ~$0.01-0.10 per report (depends on size)
       - Anthropic: ~$0.01-0.10 per report (depends on size)
       - Recommendation: Start with rule-based, upgrade to LLM for production
    
    
    8. EXAMPLE OUTPUTS
       ========================
       
       Input (corrupted):
       Report ID: Ø=abc123 Date: 2024/01/15
       URL: https://example.com/thþreathash
       Detections: 12/67 þthreat_type: trojan
       
       Output (cleaned markdown):
       # Security Scan Report
       **Report ID:** abc123
       **Scan Date:** 2024-01-15
       
       ## Threat Assessment
       **Threat Level:** MEDIUM
       **Detection Rate:** 17.9%
       **Recommended Action:** URGENT (1-7 days)
       
       ## Analyzed URLs
       - `https://example.com/threathash`
       
       [... complete formatted report ...]
    """


# ============================================================================
# QUICK START EXAMPLES
# ============================================================================

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("REPORT CLEANER - INTEGRATION EXAMPLES")
    print("=" * 70)
    
    # Example 1: Basic rule-based cleaning
    print("\n1. RULE-BASED CLEANING (No API keys needed):")
    print("-" * 70)
    try:
        method1_rule_based()
    except Exception as e:
        print(f"Error: {e}")
    
    # Example 2: LLM-based with fallback
    print("\n\n2. LLM-BASED CLEANING (OpenAI/Anthropic, with fallback):")
    print("-" * 70)
    try:
        method2_llm_based()
    except Exception as e:
        print(f"Error (expected if no API key): {e}")
        print("Tip: Set OPENAI_API_KEY or ANTHROPIC_API_KEY to enable LLM cleaning")
    
    # Example 3: Setup instructions
    print("\n\n3. SETUP INSTRUCTIONS:")
    print("-" * 70)
    print(setup_instructions())
