#!/usr/bin/env python3
"""
Professional Report Cleaner - Transforms raw malware sniffer reports into clean markdown format
Handles junk characters, encoding issues, and standardizes report structure.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Risk classification tiers based on detection percentages."""
    SAFE = "SAFE"           # 0-5% detections
    LOW = "LOW"             # 5-15% detections
    MEDIUM = "MEDIUM"       # 15-40% detections
    HIGH = "HIGH"           # 40-75% detections
    CRITICAL = "CRITICAL"   # 75-100% detections


class ActionUrgency(Enum):
    """Action prioritization by timeframe."""
    IMMEDIATE = "IMMEDIATE (0-24 hours)"
    URGENT = "URGENT (1-7 days)"
    STANDARD = "STANDARD (1-3 months)"
    LOW_PRIORITY = "LOW PRIORITY (3+ months)"


class ReportCleaner:
    """
    Professional security report parser and formatter.
    
    Handles:
    - Junk character removal (encoding artifacts)
    - Status normalization
    - Risk classification
    - Action prioritization
    - Table formatting
    """
    
    # Junk characters commonly found in corrupted PDFs
    JUNK_CHARS = {
        '�': '',           # Replacement character
        'Ø': '',           # Corrupted O with stroke
        'Ø=': '',          # Corrupted byte sequence
        'þ': '',           # Thorn character (corrupted)
        'Ÿ': '',           # Y with diaeresis (corrupted)
        'ÿ': '',           # Y with diaeresis lowercase (corrupted)
        '\x00': '',        # Null byte
        '\ufffd': '',      # Unicode replacement
        '\x1a': '',        # EOF marker
        '™': '',           # Trademark symbol (spurious)
        '©': '',           # Copyright (if spurious)
    }
    
    # Status normalization mapping
    STATUS_MAP = {
        'clear': 'CLEAR',
        'clean': 'CLEAR',
        'safe': 'CLEAR',
        'no threats': 'CLEAR',
        'detected': 'DETECTED',
        'found': 'DETECTED',
        'threat': 'DETECTED',
        'malware': 'DETECTED',
        'absent': 'ABSENT',
        'not detected': 'ABSENT',
        'not found': 'ABSENT',
        'none': 'ABSENT',
        'n/a': 'N/A',
        'unknown': 'N/A',
        'pending': 'N/A',
    }
    
    def __init__(self):
        """Initialize the report cleaner."""
        self.junk_pattern = self._create_junk_pattern()
    
    def _create_junk_pattern(self) -> str:
        """Create regex pattern for junk characters."""
        chars = '|'.join(re.escape(char) for char in self.JUNK_CHARS.keys())
        return f"({chars})"
    
    def clean_text(self, text: str) -> str:
        """
        Remove junk characters and encoding artifacts.
        
        Args:
            text: Raw text potentially containing junk characters
            
        Returns:
            Cleaned text with artifacts removed
        """
        if not text:
            return ""
        
        # Replace junk characters
        cleaned = re.sub(self.junk_pattern, '', text)
        
        # Remove multiple consecutive spaces
        cleaned = re.sub(r' {2,}', ' ', cleaned)
        
        # Remove multiple consecutive newlines
        cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
        
        # Strip leading/trailing whitespace from lines
        lines = [line.strip() for line in cleaned.split('\n')]
        cleaned = '\n'.join(lines)
        
        return cleaned.strip()
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract and clean URLs from text."""
        url_pattern = r'https?://[^\s\)"\']+'
        urls = re.findall(url_pattern, text)
        
        # Clean URLs of trailing punctuation
        cleaned_urls = []
        for url in urls:
            url = url.rstrip('.,;:!?')
            if url and not url.endswith('..'):
                cleaned_urls.append(url)
        
        return list(set(cleaned_urls))  # Remove duplicates
    
    def extract_dates(self, text: str) -> List[str]:
        """Extract dates from text."""
        date_patterns = [
            r'\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'\d{1,2}/\d{1,2}/\d{4}',  # MM/DD/YYYY
            r'\d{1,2}-\d{1,2}-\d{4}',  # MM-DD-YYYY
            r'\d{1,2}\s(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s\d{4}',  # DD Mon YYYY
        ]
        
        dates = []
        for pattern in date_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            dates.extend(matches)
        
        return list(set(dates))
    
    def classify_threat_level(self, detection_percentage: float) -> ThreatLevel:
        """
        Classify threat level based on detection percentage.
        
        Args:
            detection_percentage: Percentage of AV engines detecting threat (0-100)
            
        Returns:
            ThreatLevel enum
        """
        if detection_percentage < 5:
            return ThreatLevel.SAFE
        elif detection_percentage < 15:
            return ThreatLevel.LOW
        elif detection_percentage < 40:
            return ThreatLevel.MEDIUM
        elif detection_percentage < 75:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL
    
    def get_action_urgency(self, threat_level: ThreatLevel) -> ActionUrgency:
        """
        Determine action urgency based on threat level.
        
        Args:
            threat_level: The classified threat level
            
        Returns:
            ActionUrgency enum
        """
        urgency_map = {
            ThreatLevel.SAFE: ActionUrgency.LOW_PRIORITY,
            ThreatLevel.LOW: ActionUrgency.STANDARD,
            ThreatLevel.MEDIUM: ActionUrgency.URGENT,
            ThreatLevel.HIGH: ActionUrgency.URGENT,
            ThreatLevel.CRITICAL: ActionUrgency.IMMEDIATE,
        }
        return urgency_map.get(threat_level, ActionUrgency.STANDARD)
    
    def detect_threat_type(self, detections: List[Dict]) -> Optional[str]:
        """
        Detect specific threat type from detection results.
        
        Args:
            detections: List of detection dictionaries
            
        Returns:
            Threat type string (Trojan, Ransomware, Spyware, Worm, Rootkit, Adware, Polymorphic) or None
        """
        if not detections:
            return None
        
        threat_keywords = {
            'Ransomware': ['ransomware', 'cryptolocker', 'wannacry', 'notpetya', '.encrypted', '.locked'],
            'Trojan': ['trojan', 'backdoor', 'rat', 'c2', 'command', 'control'],
            'Rootkit': ['rootkit', 'bootkit', 'kernel', 'firmware'],
            'Spyware': ['spyware', 'keylogger', 'infostealer', 'stealer', 'password'],
            'Worm': ['worm', 'propagat', 'network spread', 'fileshare'],
            'Polymorphic': ['polymorphic', 'metamorphic', 'variant', 'mutation'],
            'Adware': ['adware', 'pup', 'potentially unwanted', 'browser hijacker'],
        }
        
        all_detections_text = ' '.join([
            d.get('detection', '').lower() + ' ' + 
            d.get('engine', '').lower() 
            for d in detections
        ])
        
        for threat_type, keywords in threat_keywords.items():
            if any(keyword in all_detections_text for keyword in keywords):
                return threat_type
        
        return None
    
    def generate_dynamic_recommendations(self, cleaned_data: Dict) -> List[str]:
        """
        Generate context-aware recommendations based on actual scan results.
        
        Args:
            cleaned_data: Dictionary with cleaned report data
            
        Returns:
            List of recommendations specific to this scan
        """
        recommendations = []
        
        detection_rate = float(cleaned_data.get('detection_rate', '0').replace('%', '')) if cleaned_data.get('detection_rate') else 0
        threat_level = cleaned_data.get('threat_level', 'SAFE')
        detections = cleaned_data.get('detections', [])
        threat_type = self.detect_threat_type(detections)
        
        # NO DETECTIONS (0% or very low)
        if detection_rate < 5:
            recommendations = [
                "No immediate action required - file appears clean",
                "Verify digital signature and source authenticity",
                "Consider whitelisting if from trusted source",
                "Monitor file behavior if executed in production",
                "Include in routine security audit logs",
            ]
        
        # TROJAN detected
        elif threat_type == 'Trojan' or 'trojan' in ' '.join([d.get('detection', '').lower() for d in detections]):
            recommendations = [
                "IMMEDIATE (0-24h): Isolate affected system from network immediately",
                "IMMEDIATE: Terminate all processes associated with the file",
                "IMMEDIATE: Disconnect from internet to prevent C2 communication",
                "IMMEDIATE: Enable EDR monitoring on affected endpoints",
                "SHORT-TERM (1-7d): Scan all systems that accessed the file",
                "SHORT-TERM: Check for lateral movement indicators",
                "SHORT-TERM: Review authentication logs for unauthorized access",
                "SHORT-TERM: Analyze network traffic for C2 server connections",
                "SHORT-TERM: Extract IOCs (IP addresses, domains, registry keys)",
                "MEDIUM-TERM (1-3mo): Implement application whitelisting",
                "MEDIUM-TERM: Update firewall rules to block identified C2 domains",
                "MEDIUM-TERM: Conduct user security awareness training",
            ]
        
        # RANSOMWARE detected
        elif threat_type == 'Ransomware' or 'ransomware' in ' '.join([d.get('detection', '').lower() for d in detections]):
            recommendations = [
                "CRITICAL - IMMEDIATE (0-24h): ISOLATE SYSTEM IMMEDIATELY",
                "IMMEDIATE: Power down affected machines to prevent encryption spread",
                "IMMEDIATE: DO NOT PAY RANSOM - contact law enforcement",
                "IMMEDIATE: Disable network shares and mapped drives",
                "IMMEDIATE: Alert all users to avoid opening suspicious files",
                "IMMEDIATE: Activate incident response team",
                "SHORT-TERM (1-7d): Identify patient zero and infection vector",
                "SHORT-TERM: Check backup integrity before restoration",
                "SHORT-TERM: Monitor for high disk I/O activity on other systems",
                "SHORT-TERM: Scan for ransomware file extensions (.encrypted, .locked)",
                "SHORT-TERM: Document encryption timeline for forensics",
                "MEDIUM-TERM (1-3mo): Implement offline backup strategy (3-2-1 rule)",
                "MEDIUM-TERM: Deploy anti-ransomware endpoint protection",
                "MEDIUM-TERM: Create KRIs for ransomware indicators",
                "MEDIUM-TERM: Patch all internet-facing vulnerabilities",
            ]
        
        # SPYWARE/KEYLOGGER detected
        elif threat_type == 'Spyware' or any(t in ' '.join([d.get('detection', '').lower() for d in detections]) for t in ['spyware', 'keylogger', 'stealer']):
            recommendations = [
                "IMMEDIATE (0-24h): Force password reset for all accounts used on infected system",
                "IMMEDIATE: Disconnect system from network",
                "IMMEDIATE: Review recent data exfiltration attempts",
                "IMMEDIATE: Enable MFA on all critical accounts",
                "SHORT-TERM (1-7d): Analyze clipboard history and keystroke logs",
                "SHORT-TERM: Check for unauthorized remote access tools",
                "SHORT-TERM: Review email sent from compromised accounts",
                "SHORT-TERM: Scan for additional persistence mechanisms",
                "SHORT-TERM: Investigate network connections to untrusted IPs",
                "MEDIUM-TERM (1-3mo): Deploy data loss prevention (DLP) solutions",
                "MEDIUM-TERM: Implement privileged access management (PAM)",
                "MEDIUM-TERM: Encrypt sensitive data at rest and in transit",
                "MEDIUM-TERM: Conduct privacy impact assessment",
            ]
        
        # WORM detected
        elif threat_type == 'Worm' or 'worm' in ' '.join([d.get('detection', '').lower() for d in detections]):
            recommendations = [
                "IMMEDIATE (0-24h): Segment network to contain spread",
                "IMMEDIATE: Disable file sharing protocols (SMB, FTP)",
                "IMMEDIATE: Block identified propagation ports at firewall",
                "IMMEDIATE: Isolate all infected systems",
                "SHORT-TERM (1-7d): Map infection spread using network logs",
                "SHORT-TERM: Patch vulnerabilities exploited for propagation",
                "SHORT-TERM: Clean all infected systems in coordinated operation",
                "SHORT-TERM: Update antivirus signatures across organization",
                "MEDIUM-TERM (1-3mo): Implement network access control (NAC)",
                "MEDIUM-TERM: Deploy intrusion prevention system (IPS)",
                "MEDIUM-TERM: Create network segmentation strategy",
                "MEDIUM-TERM: Establish vulnerability management program",
            ]
        
        # ROOTKIT detected
        elif threat_type == 'Rootkit' or 'rootkit' in ' '.join([d.get('detection', '').lower() for d in detections]):
            recommendations = [
                "CRITICAL - IMMEDIATE (0-24h): ASSUME FULL SYSTEM COMPROMISE",
                "IMMEDIATE: Do not trust OS utilities - boot from clean external media",
                "IMMEDIATE: Capture memory dump for forensics",
                "IMMEDIATE: Prepare for complete system rebuild",
                "SHORT-TERM (1-7d): Perform offline disk imaging before remediation",
                "SHORT-TERM: Check BIOS/UEFI for firmware rootkits",
                "SHORT-TERM: Analyze Master Boot Record (MBR) for modifications",
                "SHORT-TERM: Use specialized rootkit detection tools",
                "SHORT-TERM: Document all registry modifications and hidden processes",
                "MEDIUM-TERM (1-3mo): Enable Secure Boot and UEFI firmware protection",
                "MEDIUM-TERM: Implement integrity monitoring tools",
                "MEDIUM-TERM: Deploy behavior-based endpoint detection",
                "MEDIUM-TERM: Conduct full security audit of privileged accounts",
            ]
        
        # ADWARE/PUP detected
        elif threat_type == 'Adware' or any(t in ' '.join([d.get('detection', '').lower() for d in detections]) for t in ['adware', 'pup', 'unwanted']):
            recommendations = [
                "LOW PRIORITY - Schedule cleanup during maintenance window",
                "Review browser extensions and installed programs",
                "Block known adware domains at DNS level",
                "Uninstall unwanted software through proper channels",
                "Clear browser cache and reset homepage settings",
                "Update browser security settings",
                "Educate users on safe software installation practices",
                "Implement software installation policies",
                "Use application control to prevent PUP installation",
            ]
        
        # POLYMORPHIC/METAMORPHIC detected
        elif threat_type == 'Polymorphic' or any(t in ' '.join([d.get('detection', '').lower() for d in detections]) for t in ['polymorphic', 'metamorphic']):
            recommendations = [
                "CRITICAL - IMMEDIATE (0-24h): Cannot rely on signature detection - ISOLATE IMMEDIATELY",
                "IMMEDIATE: Enable heuristic and behavioral analysis tools",
                "IMMEDIATE: Submit sample to sandbox for dynamic analysis",
                "SHORT-TERM (1-7d): Deploy AI/ML-based malware detection",
                "SHORT-TERM: Monitor for code mutation patterns",
                "SHORT-TERM: Create behavioral IOCs rather than signature-based",
                "SHORT-TERM: Check for process injection and API hooking",
                "MEDIUM-TERM (1-3mo): Upgrade to next-gen antivirus with behavioral detection",
                "MEDIUM-TERM: Implement continuous monitoring and threat hunting",
                "MEDIUM-TERM: Establish threat intelligence feeds",
                "MEDIUM-TERM: Train SOC team on advanced malware analysis",
            ]
        
        # Detection rate-based recommendations (if no specific threat type)
        elif detection_rate > 60:
            recommendations = [
                "IMMEDIATE (0-24h): Treat as confirmed threat requiring action",
                "IMMEDIATE: Update security signatures immediately",
                "SHORT-TERM (1-7d): Check for threat intelligence reports on detected malware",
                "SHORT-TERM: Investigate why some scanners may have missed it",
                "MEDIUM-TERM (1-3mo): Follow standard containment and remediation procedures",
            ]
        elif detection_rate > 40:
            recommendations = [
                "URGENT (1-7d): Treat as confirmed threat with some evasion capabilities",
                "URGENT: Update security signatures immediately",
                "SHORT-TERM: Check for threat intelligence reports on detected malware",
                "MEDIUM-TERM (1-3mo): Investigate why some scanners missed it",
            ]
        elif detection_rate > 15:
            recommendations = [
                "Verify with additional sandboxing analysis",
                "Submit to multiple online scanning services",
                "Monitor file behavior in isolated environment",
                "Consider as potential zero-day threat",
                "Upload to VirusTotal for community analysis",
            ]
        
        return recommendations

    def normalize_status(self, status: str) -> str:
        """
        Normalize status to standard terms.
        
        Args:
            status: Raw status string from report
            
        Returns:
            Normalized status (CLEAR, DETECTED, ABSENT, or N/A)
        """
        if not status:
            return "N/A"
        
        status_lower = status.lower().strip()
        
        # Check direct matches first
        if status_lower in self.STATUS_MAP:
            return self.STATUS_MAP[status_lower]
        
        # Check partial matches
        for key, value in self.STATUS_MAP.items():
            if key in status_lower:
                return value
        
        # Default to N/A for unknown statuses
        return "N/A"
    
    def extract_report_id(self, text: str) -> Optional[str]:
        """
        Extract report ID/hash from text.
        
        Args:
            text: Text potentially containing report ID
            
        Returns:
            Report ID if found, None otherwise
        """
        # Look for common ID patterns
        patterns = [
            r'(?:Report|Scan) ID:?\s*([a-zA-Z0-9_\-]{15,})',
            r'ID:?\s*([a-zA-Z0-9_\-]{15,})',
            r'(?:File|Object) Hash:?\s*([a-f0-9]{32,})',
            r'(?:MD5|SHA256):?\s*([a-f0-9]{32,})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def parse_detection_table(self, text: str) -> List[Dict[str, str]]:
        """
        Parse detection table from report text.
        
        Args:
            text: Text containing table data
            
        Returns:
            List of dictionaries representing table rows
        """
        rows = []
        
        # Split text into lines and look for table-like patterns
        lines = text.split('\n')
        
        for line in lines:
            # Skip empty lines and headers
            if not line.strip() or 'detection' in line.lower():
                continue
            
            # Simple pattern: engine name | status | details
            parts = [p.strip() for p in line.split('|')]
            
            if len(parts) >= 2:
                row = {
                    'engine': self.clean_text(parts[0]),
                    'status': self.normalize_status(parts[1]) if len(parts) > 1 else 'N/A',
                    'detection': self.clean_text(parts[2]) if len(parts) > 2 else '',
                }
                
                # Only add if engine name is reasonable length
                if 2 < len(row['engine']) < 50:
                    rows.append(row)
        
        return rows
    
    def format_as_markdown(self, cleaned_data: Dict) -> str:
        """
        Format cleaned report data as professional markdown.
        
        Args:
            cleaned_data: Dictionary containing cleaned report data
            
        Returns:
            Formatted markdown string
        """
        markdown = []
        
        # Header
        if cleaned_data.get('report_id'):
            markdown.append(f"# Security Scan Report")
            markdown.append(f"**Report ID:** {cleaned_data['report_id']}\n")
        
        if cleaned_data.get('scan_date'):
            markdown.append(f"**Scan Date:** {cleaned_data['scan_date']}")
        
        # Threat Summary
        if cleaned_data.get('threat_level'):
            markdown.append(f"\n## Threat Assessment\n")
            markdown.append(f"**Threat Level:** {cleaned_data['threat_level']}")
            markdown.append(f"**Detection Rate:** {cleaned_data.get('detection_rate', 'N/A')}")
            markdown.append(f"**Recommended Action:** {cleaned_data.get('action_urgency', 'N/A')}\n")
        
        # URLs
        if cleaned_data.get('urls'):
            markdown.append(f"\n## Analyzed URLs\n")
            for url in cleaned_data['urls']:
                markdown.append(f"- `{url}`")
            markdown.append("")
        
        # Detection Details
        if cleaned_data.get('detections'):
            markdown.append(f"\n## Detection Details\n")
            markdown.append("| Engine | Status | Detection |")
            markdown.append("|--------|--------|-----------|")
            for det in cleaned_data['detections']:
                engine = det.get('engine', 'Unknown')
                status = det.get('status', 'N/A')
                detection = det.get('detection', '')
                markdown.append(f"| {engine} | {status} | {detection} |")
            markdown.append("")
        
        # Recommendations
        if cleaned_data.get('recommendations'):
            markdown.append(f"\n## Recommendations\n")
            for rec in cleaned_data['recommendations']:
                markdown.append(f"- {rec}")
            markdown.append("")
        
        # Metadata
        markdown.append(f"\n## Report Metadata\n")
        markdown.append(f"- **Generated:** {datetime.now().isoformat()}")
        markdown.append(f"- **Status:** Cleaned and formatted")
        
        return '\n'.join(markdown)
    
    def process_report(self, raw_report: str) -> Dict:
        """
        Complete report processing pipeline.
        
        Args:
            raw_report: Raw malware sniffer report with potential junk characters
            
        Returns:
            Dictionary with cleaned report data
        """
        try:
            # Clean the text
            cleaned_text = self.clean_text(raw_report)
            
            # Extract structured data
            report_id = self.extract_report_id(cleaned_text)
            urls = self.extract_urls(cleaned_text)
            dates = self.extract_dates(cleaned_text)
            detections = self.parse_detection_table(cleaned_text)
            
            # Calculate detection statistics
            detected_count = sum(1 for d in detections if d['status'] == 'DETECTED')
            total_count = len(detections) if detections else 1
            detection_percentage = (detected_count / total_count) * 100 if total_count > 0 else 0
            
            # Classify threat level
            threat_level = self.classify_threat_level(detection_percentage)
            action_urgency = self.get_action_urgency(threat_level)
            
            # Compile cleaned data first (needed for dynamic recommendations)
            cleaned_data_base = {
                'original_length': len(raw_report),
                'cleaned_length': len(cleaned_text),
                'report_id': report_id,
                'scan_date': dates[0] if dates else 'Unknown',
                'urls': urls,
                'detections': detections,
                'threat_level': threat_level.value,
                'detection_rate': f"{detection_percentage:.1f}%",
                'action_urgency': action_urgency.value,
                'cleaned_text': cleaned_text,
            }
            
            # Generate context-aware recommendations based on actual scan results
            recommendations = self.generate_dynamic_recommendations(cleaned_data_base)
            
            # Add recommendations to cleaned data
            cleaned_data = cleaned_data_base.copy()
            cleaned_data['recommendations'] = recommendations
            
            logger.info(f"Report processed: {report_id or 'Unknown ID'}")
            logger.info(f"Threat Level: {threat_level.value}, Detection Rate: {detection_percentage:.1f}%")
            logger.info(f"Generated {len(recommendations)} context-specific recommendations")
            
            return cleaned_data
            
        except Exception as e:
            logger.error(f"Error processing report: {e}")
            return {
                'error': str(e),
                'original_length': len(raw_report),
            }
    
    def _generate_recommendations(self, threat_level: ThreatLevel, urls: List[str]) -> List[str]:
        """Generate action recommendations based on threat level."""
        recommendations = []
        
        if threat_level == ThreatLevel.CRITICAL:
            recommendations.extend([
                "🚨 IMMEDIATE ACTION REQUIRED: Isolate affected systems from network",
                "Block all identified URLs at firewall/proxy level",
                "Scan entire system and connected devices with updated antivirus",
                "Review recent file downloads and email attachments",
                "Enable enhanced monitoring and logging",
            ])
        elif threat_level == ThreatLevel.HIGH:
            recommendations.extend([
                "⚠️ URGENT: Run full system scan with multiple antivirus engines",
                "Block identified URLs in your security appliances",
                "Review and strengthen email filtering rules",
                "Consider network segmentation for affected assets",
                "Enable real-time file monitoring",
            ])
        elif threat_level == ThreatLevel.MEDIUM:
            recommendations.extend([
                "Update antivirus definitions immediately",
                "Run scheduled system scan",
                "Monitor system behavior for anomalies",
                "Review web filtering policies",
                "Keep systems patched and updated",
            ])
        elif threat_level == ThreatLevel.LOW:
            recommendations.extend([
                "Standard security monitoring continues",
                "Maintain updated antivirus definitions",
                "Regular system scans recommended",
                "Keep systems patched",
            ])
        else:  # SAFE
            recommendations.extend([
                "No immediate action required",
                "Continue standard security practices",
                "Maintain routine system maintenance",
            ])
        
        return recommendations



def create_llm_prompt() -> str:
    """
    Create a comprehensive system prompt for LLM-based report cleaning.
    Can be used with OpenAI, Anthropic, or other LLM APIs.
    """
    return """You are a professional security report parser and formatter with expertise in malware analysis, threat intelligence, and cybersecurity reporting.

## Your Role
Transform raw, corrupted malware sniffer reports (with encoding issues, junk characters, and formatting problems) into clean, professional markdown documents that are clear and actionable.

## Input Format
You will receive raw PDF text extracts that may contain:
- Encoding artifacts (corrupted characters like: Ø=, þ, ÿ, ™, etc.)
- Garbled text and random characters from encoding errors
- Inconsistent formatting and table structures
- Truncated or incomplete information
- Multiple newlines and spacing issues

## Processing Rules

### 1. Data Extraction Guidelines
- Strip all junk characters and encoding artifacts
- Preserve URLs, file hashes, and report IDs exactly as they appear (after cleaning)
- Maintain dates in ISO format (YYYY-MM-DD)
- Extract all antivirus engine detection results
- Keep all legitimate alphanumeric content

### 2. Status Normalization
Standardize detection statuses to these four categories:
- **CLEAR**: When AV engine found nothing (also: clean, safe, no threats)
- **DETECTED**: When malware/threat was found (also: found, threat, malware)
- **ABSENT**: When explicitly stated as not detected (also: not found, none)
- **N/A**: For unknown, pending, or unclear statuses

### 3. Risk Classification (based on detection percentage)
- **SAFE**: 0-5% of AV engines detect the threat
- **LOW**: 5-15% detection rate
- **MEDIUM**: 15-40% detection rate
- **HIGH**: 40-75% detection rate
- **CRITICAL**: 75-100% detection rate

### 4. Action Prioritization by Urgency
- **IMMEDIATE (0-24 hours)**: For CRITICAL and HIGH threats
- **URGENT (1-7 days)**: For MEDIUM threats
- **STANDARD (1-3 months)**: For LOW threats
- **LOW PRIORITY (3+ months)**: For SAFE items

### 5. Edge Case Handling
- **Missing data**: Mark as "Unknown" or "N/A" - do not fabricate data
- **Truncated URLs**: Keep what's available, mark incomplete
- **Partial hashes**: Preserve as-is with note "[truncated]"
- **Unclear dates**: Use available information or omit with explanation
- **Mixed languages**: Preserve as-is after cleaning corruption

## Output Format

Structure the cleaned report as markdown with:
1. **Report Header** (Report ID, Scan Date)
2. **Threat Assessment** (Overall risk level, detection rate, recommended action)
3. **Analyzed URLs** (All extracted URLs in code blocks)
4. **Detection Details** (Table format: Engine | Status | Detection)
5. **Recommendations** (Action items based on threat level)
6. **Report Metadata** (Processing timestamp, status)

## Quality Checklist
Before finalizing each report, verify:
- ✅ All junk characters removed (should see NO: Ø, þ, ÿ, ™, or garbled text)
- ✅ Table formatting is consistent and readable
- ✅ All URLs are properly formatted and complete
- ✅ All dates are in standard format
- ✅ Report ID is identified or marked as "Unknown"
- ✅ All sections present or marked as "Not provided"
- ✅ Status values are normalized to four standard options
- ✅ No fabricated data - only cleaned original content

## Example Transformation

**Input (corrupted):**
```
Report ID: Ø=abc123 Date: 2024/01/15
URL: https://example.com/thþreathash
Detections: 12/67 þthreat_type: trojan
Engine Results:
Kaspersky | þthreat_found | Trojan.Win32.XYZ
Norton þ | clear | N/A
```

**Output (cleaned):**
```
# Security Scan Report
**Report ID:** abc123
**Scan Date:** 2024-01-15

## Threat Assessment
**Threat Level:** MEDIUM
**Detection Rate:** 17.9%
**Recommended Action:** URGENT (1-7 days)

## Analyzed URLs
- `https://example.com/threathash`

## Detection Details
| Engine | Status | Detection |
|--------|--------|-----------|
| Kaspersky | DETECTED | Trojan.Win32.XYZ |
| Norton | CLEAR | N/A |

## Recommendations
- Run full system scan with multiple antivirus engines
- Block identified URLs in security appliances
- Review and strengthen email filtering rules

## Report Metadata
- **Generated:** 2024-01-15T10:30:00
- **Status:** Cleaned and formatted
```

## Critical Instructions
1. ONLY clean and transform - never invent missing information
2. Preserve all legitimate security-related data
3. Flag any information you cannot confidently decode
4. Maintain confidentiality of sensitive indicators
5. Ensure the output is immediately actionable by security teams
"""


if __name__ == "__main__":
    # Example usage
    cleaner = ReportCleaner()
    
    # Example raw report with junk characters
    example_report = """
    Report ID: Ø=scan123456789 Date: 2024-01-15
    URL Analyzed: https://example.com/malwareþfile.exe
    
    Detection Results: 8/67 þ threat detected
    
    Engine Detections |
    Kaspersky | þdetected | Trojan.Win32.ABC
    Norton Antivirus | clear | Safe
    AVG | detected | Generic trojan
    Avast | UNKNOWN | N/A
    """
    
    result = cleaner.process_report(example_report)
    
    print("Cleaned Report Data:")
    print(json.dumps({k: v for k, v in result.items() if k != 'cleaned_text'}, indent=2))
    
    print("\n" + "="*80)
    print("Formatted Markdown:")
    print("="*80)
    print(cleaner.format_as_markdown(result))
