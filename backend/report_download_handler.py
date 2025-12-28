#!/usr/bin/env python3
"""
Report Download Handler - Integrates report cleaner with scan downloads
Cleans and formats scan reports before sending to frontend for PDF/Excel export
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import logging
from typing import Dict, Any
from report_cleaner import ReportCleaner
from llm_report_integration import HybridReportCleaner, get_llm_provider

logger = logging.getLogger(__name__)

# Create blueprint for report operations
report_bp = Blueprint('reports', __name__, url_prefix='/api/reports')

# Initialize report cleaners (module-level, initialized once)
_rule_based_cleaner = None
_hybrid_cleaner = None

def init_cleaners():
    """Initialize report cleaners at startup."""
    global _rule_based_cleaner, _hybrid_cleaner
    _rule_based_cleaner = ReportCleaner()
    _hybrid_cleaner = HybridReportCleaner(llm_provider=get_llm_provider('auto'))

def get_rule_cleaner():
    """Get rule-based cleaner instance."""
    if _rule_based_cleaner is None:
        init_cleaners()
    return _rule_based_cleaner

def get_hybrid_cleaner():
    """Get hybrid cleaner instance."""
    if _hybrid_cleaner is None:
        init_cleaners()
    return _hybrid_cleaner


@report_bp.route('/clean', methods=['POST'])
def clean_report_endpoint():
    """
    Clean a raw scan report.
    
    POST /api/reports/clean
    
    Request body:
    {
        "raw_report": "string",  # Raw scan report text
        "use_llm": bool,         # Optional, try LLM first if true
        "scan_id": "string"      # Optional scan ID for tracking
    }
    
    Response:
    {
        "success": bool,
        "method": "string",      # "LLM-based" or "Rule-based"
        "cleaned_report": "string",  # Cleaned markdown
        "threat_data": {
            "threat_level": string,
            "detection_rate": string,
            "urls": [...],
            "recommendations": [...]
        },
        "timestamp": "ISO string"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        raw_report = data.get('raw_report')
        use_llm = data.get('use_llm', True)
        scan_id = data.get('scan_id', 'unknown')
        
        if not raw_report:
            return jsonify({'error': 'raw_report field is required'}), 400
        
        logger.info(f"Cleaning report for scan: {scan_id}")
        
        # Use hybrid cleaner for professional formatting
        cleaner = get_hybrid_cleaner()
        result = cleaner.clean_report(raw_report, use_llm=use_llm)
        
        if not result['success']:
            logger.warning(f"Report cleaning partially failed for {scan_id}: {result.get('error')}")
        
        # Prepare response
        response = {
            'success': result['success'],
            'method': result['method'],
            'cleaned_report': result['cleaned_report'],
            'threat_data': result.get('structured_data', {}),
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        if result.get('error'):
            response['error'] = result['error']
        
        logger.info(f"Report cleaned successfully for {scan_id} using {result['method']}")
        return jsonify(response), 200 if result['success'] else 202
        
    except Exception as e:
        logger.error(f"Error cleaning report: {e}", exc_info=True)
        return jsonify({'error': str(e), 'success': False}), 500


@report_bp.route('/analyze-scan', methods=['POST'])
def analyze_scan_for_report():
    """
    Analyze a scan result and prepare cleaned threat data for reports.
    
    POST /api/reports/analyze-scan
    
    Request body:
    {
        "scan_data": {...},  # Full scan object from database
        "format": "json"     # Output format: json, text, markdown
    }
    
    Response: Cleaned and structured threat data
    """
    try:
        data = request.get_json()
        scan_data = data.get('scan_data', {})
        output_format = data.get('format', 'json')
        
        if not scan_data:
            return jsonify({'error': 'scan_data required'}), 400
        
        # Convert scan data to report format
        report_text = convert_scan_to_report_text(scan_data)
        
        # Clean the report
        cleaner = get_rule_cleaner()
        cleaned_data = cleaner.process_report(report_text)
        
        # Return in requested format
        if output_format == 'markdown':
            markdown = cleaner.format_as_markdown(cleaned_data)
            return jsonify({
                'success': True,
                'format': 'markdown',
                'content': markdown,
                'threat_level': cleaned_data.get('threat_level'),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        elif output_format == 'text':
            return jsonify({
                'success': True,
                'format': 'text',
                'content': cleaned_data.get('cleaned_text'),
                'threat_level': cleaned_data.get('threat_level'),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
        else:  # json
            return jsonify({
                'success': True,
                'format': 'json',
                'content': {k: v for k, v in cleaned_data.items() 
                           if k not in ['cleaned_text', 'original_length', 'cleaned_length']},
                'threat_level': cleaned_data.get('threat_level'),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
    
    except Exception as e:
        logger.error(f"Error analyzing scan: {e}")
        return jsonify({'error': str(e), 'success': False}), 500


def convert_scan_to_report_text(scan_data: Dict[str, Any]) -> str:
    """
    Convert scan data dictionary to text report format.
    This produces the raw text that gets cleaned.
    """
    lines = []
    
    # Header
    lines.append("SECURITY SCAN REPORT")
    lines.append("=" * 50)
    
    # Basic info
    lines.append(f"\nReport ID: {scan_data.get('id', 'N/A')}")
    lines.append(f"Scan Date: {scan_data.get('timestamp', 'N/A')}")
    lines.append(f"Classification: {scan_data.get('classification', 'N/A')}")
    lines.append(f"Risk Score: {scan_data.get('overall_risk', scan_data.get('risk_score', 'N/A'))}%")
    
    # URL
    if scan_data.get('url'):
        lines.append(f"\nTarget URL: {scan_data['url']}")
    
    # Executive Summary
    lines.append("\nEXECUTIVE SUMMARY")
    lines.append("-" * 50)
    lines.append(f"Threat Level: {scan_data.get('classification', 'Unknown')}")
    lines.append(f"Overall Assessment: {scan_data.get('assessment', 'Analysis completed')}")
    
    # Key Findings
    lines.append("\nKEY FINDINGS")
    lines.append("-" * 50)
    
    if scan_data.get('key_findings'):
        for finding in scan_data['key_findings']:
            lines.append(f"- {finding}")
    else:
        lines.append("- Analysis completed")
    
    # Threat Indicators / Analysis Results
    lines.append("\nTHREAT INDICATORS")
    lines.append("-" * 50)
    lines.append("Indicator | Status | Description")
    lines.append("-" * 50)
    
    # Add threat indicators from scan
    indicators = [
        ('Obfuscated JS', scan_data.get('has_obfuscated_js', False), 'Code obfuscation in JavaScript'),
        ('Suspicious Patterns', scan_data.get('has_suspicious_patterns', False), 'Suspicious code patterns'),
        ('Password Fields', scan_data.get('has_password_fields', False), 'Password harvesting attempts'),
        ('External Scripts', scan_data.get('external_scripts_count', 0) > 0, 'External script inclusions'),
        ('Embedded IFrames', scan_data.get('iframe_count', 0) > 0, 'Embedded iframe elements'),
    ]
    
    for indicator_name, detected, description in indicators:
        status = 'DETECTED' if detected else 'CLEAR'
        lines.append(f"{indicator_name} | {status} | {description}")
    
    # Analysis Results
    lines.append("\nANALYSIS RESULTS")
    lines.append("-" * 50)
    lines.append("Metric | Value")
    lines.append("-" * 50)
    lines.append(f"Risk Score | {scan_data.get('overall_risk', 'N/A')}%")
    lines.append(f"ML Prediction | {scan_data.get('ml_prediction', 'N/A')}")
    lines.append(f"ML Confidence | {scan_data.get('ml_confidence', 'N/A')}%")
    lines.append(f"External Scripts | {scan_data.get('external_scripts_count', 0)}")
    lines.append(f"Embedded IFrames | {scan_data.get('iframe_count', 0)}")
    
    # Recommendations
    lines.append("\nRECOMMENDATIONS")
    lines.append("-" * 50)
    
    if scan_data.get('recommendations'):
        for rec in scan_data['recommendations']:
            lines.append(f"- {rec}")
    else:
        lines.append("- Continue standard security monitoring")
    
    # Footer
    lines.append(f"\nReport Generated: {datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p')}")
    
    return '\n'.join(lines)


def register_report_routes(app):
    """Register report routes with Flask app."""
    app.register_blueprint(report_bp)
    init_cleaners()
    logger.info("Report cleaning routes registered and cleaners initialized")


# For backward compatibility / direct usage
def clean_scan_report(raw_report: str, use_llm: bool = False) -> Dict[str, Any]:
    """
    Directly clean a scan report (without HTTP).
    Useful for internal processing.
    
    Args:
        raw_report: Raw scan report text
        use_llm: Whether to try LLM first
        
    Returns:
        Dictionary with cleaned report and structured data
    """
    try:
        if use_llm:
            cleaner = get_hybrid_cleaner()
        else:
            cleaner = get_rule_cleaner()
        
        if use_llm:
            result = cleaner.clean_report(raw_report)
        else:
            cleaned = cleaner.process_report(raw_report)
            result = {
                'success': True,
                'method': 'Rule-based',
                'cleaned_report': cleaner.format_as_markdown(cleaned),
                'structured_data': {k: v for k, v in cleaned.items() 
                                   if k not in ['cleaned_text', 'original_length', 'cleaned_length']}
            }
        
        return result
        
    except Exception as e:
        logger.error(f"Error cleaning report: {e}")
        return {
            'success': False,
            'error': str(e),
            'method': 'None'
        }


if __name__ == '__main__':
    # Example usage
    from report_cleaner import ReportCleaner
    
    raw = """
    Report ID: SCAN-20251227-115405
    Scan Date: 12/27/2025, 11:54:05 PM
    Classification: SUSPICIOUS
    Risk Score: 58.5%
    
    URL: https://api.workos.com/user_management/authorize?c
    
    Threat Level: SUSPICIOUS
    
    Key Findings:
    - Medium-risk authorization endpoint detected
    - No malicious JavaScript obfuscation found (CLEAR status)
    - No suspicious code patterns identified (CLEAR status)
    """
    
    result = clean_scan_report(raw, use_llm=False)
    print("Cleaned Report:")
    print(result['cleaned_report'])
