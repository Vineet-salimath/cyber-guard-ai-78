#!/usr/bin/env python3
"""
Test Suite for Report Cleaner Integration
Validates all functionality and demonstrates usage patterns
"""

import json
import logging
from report_cleaner import ReportCleaner, ThreatLevel, ActionUrgency

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TestReportCleaner:
    """Test suite for report cleaner functionality."""
    
    def __init__(self):
        self.cleaner = ReportCleaner()
        self.test_results = []
    
    def test_junk_character_removal(self):
        """Test that junk characters are properly removed."""
        print("\n" + "=" * 70)
        print("TEST 1: Junk Character Removal")
        print("=" * 70)
        
        raw_text = "Report ID: abc123þdef456 ÿStatus: CleanŸ"
        cleaned = self.cleaner.clean_text(raw_text)
        
        print(f"Original: {raw_text}")
        print(f"Cleaned:  {cleaned}")
        
        # Check that junk characters are gone (only check actual junk, not = sign)
        has_junk = any(c in cleaned for c in ['þ', 'ÿ', 'Ÿ'])
        success = not has_junk
        
        print(f"[PASS] Junk characters removed" if success else f"[FAIL] Junk characters remain")
        self.test_results.append(("Junk Character Removal", success))
    
    def test_url_extraction(self):
        """Test URL extraction from text."""
        print("\n" + "=" * 70)
        print("TEST 2: URL Extraction")
        print("=" * 70)
        
        text = """
        Found malicious URLs:
        - https://example.com/malware.exe
        - https://suspicious-site.org/phishing?token=abc123
        - http://old-protocol.net/file.zip,
        """
        
        urls = self.cleaner.extract_urls(text)
        
        print(f"Extracted URLs:")
        for url in urls:
            print(f"  - {url}")
        
        expected_urls = 3
        success = len(urls) == expected_urls
        
        print(f"[PASS] Extracted {len(urls)} URLs" if success else f"[FAIL] Expected {expected_urls} URLs")
        self.test_results.append(("URL Extraction", success))
    
    def test_threat_level_classification(self):
        """Test threat level classification."""
        print("\n" + "=" * 70)
        print("TEST 3: Threat Level Classification")
        print("=" * 70)
        
        test_cases = [
            (2.0, ThreatLevel.SAFE, "2% detection"),
            (10.0, ThreatLevel.LOW, "10% detection"),
            (30.0, ThreatLevel.MEDIUM, "30% detection"),
            (60.0, ThreatLevel.HIGH, "60% detection"),
            (90.0, ThreatLevel.CRITICAL, "90% detection"),
        ]
        
        all_passed = True
        
        for percentage, expected, description in test_cases:
            result = self.cleaner.classify_threat_level(percentage)
            passed = result == expected
            status = "[OK]" if passed else "[FAIL]"
            print(f"{status} {description} -> {result.value} (expected: {expected.value})")
            all_passed = all_passed and passed
        
        self.test_results.append(("Threat Level Classification", all_passed))
    
    def test_status_normalization(self):
        """Test status normalization."""
        print("\n" + "=" * 70)
        print("TEST 4: Status Normalization")
        print("=" * 70)
        
        test_cases = [
            ("clear", "CLEAR"),
            ("DETECTED", "DETECTED"),
            ("not found", "ABSENT"),
            ("unknown", "N/A"),
            ("safe", "CLEAR"),
            ("malware found", "DETECTED"),
            ("N/A", "N/A"),
        ]
        
        all_passed = True
        
        for input_status, expected in test_cases:
            result = self.cleaner.normalize_status(input_status)
            passed = result == expected
            status = "[OK]" if passed else "[FAIL]"
            print(f"{status} '{input_status}' -> {result} (expected: {expected})")
            all_passed = all_passed and passed
        
        self.test_results.append(("Status Normalization", all_passed))
    
    def test_action_urgency(self):
        """Test action urgency mapping."""
        print("\n" + "=" * 70)
        print("TEST 5: Action Urgency Mapping")
        print("=" * 70)
        
        test_cases = [
            (ThreatLevel.SAFE, ActionUrgency.LOW_PRIORITY),
            (ThreatLevel.LOW, ActionUrgency.STANDARD),
            (ThreatLevel.MEDIUM, ActionUrgency.URGENT),
            (ThreatLevel.HIGH, ActionUrgency.URGENT),
            (ThreatLevel.CRITICAL, ActionUrgency.IMMEDIATE),
        ]
        
        all_passed = True
        
        for threat_level, expected in test_cases:
            result = self.cleaner.get_action_urgency(threat_level)
            passed = result == expected
            status = "[OK]" if passed else "[FAIL]"
            print(f"{status} {threat_level.value} -> {result.value}")
            all_passed = all_passed and passed
        
        self.test_results.append(("Action Urgency Mapping", all_passed))
    
    def test_date_extraction(self):
        """Test date extraction."""
        print("\n" + "=" * 70)
        print("TEST 6: Date Extraction")
        print("=" * 70)
        
        text = """
        Scan performed on 2024-01-15.
        Previous scan: 01/14/2024
        Report date: 14-Jan-2024
        """
        
        dates = self.cleaner.extract_dates(text)
        
        print(f"Extracted dates:")
        for date in dates:
            print(f"  - {date}")
        
        success = len(dates) > 0
        
        print(f"[PASS] Extracted {len(dates)} dates" if success else f"[FAIL] No dates extracted")
        self.test_results.append(("Date Extraction", success))
    
    def test_full_report_processing(self):
        """Test complete report processing pipeline."""
        print("\n" + "=" * 70)
        print("TEST 7: Full Report Processing Pipeline")
        print("=" * 70)
        
        # Realistic malware sniffer report with junk
        raw_report = """
        ========================================
        Malware Detection Report
        ========================================
        
        Scan ID: SCAN_001234567890abcdefghij
        Date: 2024-01-15
        Threat Status: Ø=malicious_detected
        URL Analyzed: https://malicious-domain.xyz/backdoor.exeþmalware
        
        File Hash (MD5): d41d8cd98f00b204e9800998ecf8427e
        
        Antivirus Scan Results: 25/70 þ threats detected
        
        Detection Engine Results:
        ===========================
        Kaspersky | detected | Trojan.Win32.Emotet.Q
        Norton Antivirus | clear | Safe
        AVG Antivirus | þdetected | Generic trojan
        Avast Security | UNKNOWN | N/A
        McAfee | detected | Backdoor.Emotet
        Windows Defender | clear | Safe
        Bitdefender | detected | Trojan.Generic
        Trend Micro | N/A | Not scanned
        
        Risk Assessment: HIGH
        Confidence: 85%
        
        Recommendation: BLOCK IMMEDIATELY þ Isolate affected systems
        """
        
        # Process the report
        result = self.cleaner.process_report(raw_report)
        
        # Verify key fields
        checks = {
            'Report ID identified': result.get('report_id') is not None,
            'URLs extracted': len(result.get('urls', [])) > 0,
            'Detections parsed': len(result.get('detections', [])) > 0,
            'Threat level classified': result.get('threat_level') is not None,
            'Detection rate calculated': result.get('detection_rate') is not None,
            'Actions recommended': len(result.get('recommendations', [])) > 0,
        }
        
        for check_name, passed in checks.items():
            status = "[OK]" if passed else "[FAIL]"
            print(f"{status} {check_name}")
        
        all_passed = all(checks.values())
        
        if all_passed:
            print(f"\nReport Summary:")
            print(f"  - Report ID: {result.get('report_id', 'Unknown')}")
            print(f"  - Scan Date: {result.get('scan_date')}")
            print(f"  - Threat Level: {result.get('threat_level')}")
            print(f"  - Detection Rate: {result.get('detection_rate')}")
            print(f"  - URLs Found: {len(result.get('urls', []))}")
            print(f"  - Engines Scanned: {len(result.get('detections', []))}")
        
        self.test_results.append(("Full Report Processing", all_passed))
    
    def test_markdown_formatting(self):
        """Test markdown output formatting."""
        print("\n" + "=" * 70)
        print("TEST 8: Markdown Formatting")
        print("=" * 70)
        
        # Simple report for formatting test
        raw_report = """
        Report ID: test_001 Date: 2024-01-15
        URL: https://example.com/malware
        Kaspersky | detected | Trojan.ABC
        Norton | clear | Safe
        """
        
        result = self.cleaner.process_report(raw_report)
        markdown = self.cleaner.format_as_markdown(result)
        
        # Check for required markdown elements
        checks = {
            'Contains threat assessment header': '## Threat Assessment' in markdown,
            'Contains URLs section': '## Analyzed URLs' in markdown,
            'Contains detection details table': '## Detection Details' in markdown,
            'Contains recommendations': '## Recommendations' in markdown,
            'Contains metadata': '## Report Metadata' in markdown,
            'Proper markdown table format': '|' in markdown,
        }
        
        for check_name, passed in checks.items():
            status = "[OK]" if passed else "[FAIL]"
            print(f"{status} {check_name}")
        
        all_passed = all(checks.values())
        
        if all_passed:
            print("\nMarkdown Output Preview:")
            print("-" * 70)
            # Print first 500 chars
            preview = markdown[:500] + "..." if len(markdown) > 500 else markdown
            print(preview)
        
        self.test_results.append(("Markdown Formatting", all_passed))
    
    def run_all_tests(self):
        """Run all tests and generate report."""
        print("\n" * 2)
        print("=" * 70)
        print("REPORT CLEANER TEST SUITE")
        print("=" * 70)
        
        try:
            self.test_junk_character_removal()
            self.test_url_extraction()
            self.test_threat_level_classification()
            self.test_status_normalization()
            self.test_action_urgency()
            self.test_date_extraction()
            self.test_full_report_processing()
            self.test_markdown_formatting()
        except Exception as e:
            logger.error(f"Test suite error: {e}")
            print(f"\n❌ ERROR: {e}")
        
        # Generate summary
        self._print_summary()
    
    def _print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        total = len(self.test_results)
        passed = sum(1 for _, result in self.test_results if result)
        failed = total - passed
        
        for test_name, result in self.test_results:
            status = "[PASS]" if result else "[FAIL]"
            print(f"{status}: {test_name}")
        
        print("\n" + "-" * 70)
        print(f"Total Tests: {total}")
        print(f"Passed: {passed} ({100*passed//total}%)")
        print(f"Failed: {failed}")
        print("=" * 70)
        
        if failed == 0:
            print("\n>>> ALL TESTS PASSED! <<<")
        
        return passed, failed


if __name__ == "__main__":
    tester = TestReportCleaner()
    tester.run_all_tests()
