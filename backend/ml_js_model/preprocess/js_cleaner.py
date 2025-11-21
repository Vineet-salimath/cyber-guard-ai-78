"""
JavaScript Cleaning and Normalization Module

Cleans and normalizes raw JavaScript code before feature extraction.
"""

import re
import jsbeautifier


class JSCleaner:
    """
    Cleans and normalizes JavaScript code for analysis.
    """
    
    def __init__(self):
        """Initialize the cleaner."""
        self.beautifier_options = jsbeautifier.default_options()
        self.beautifier_options.indent_size = 2
        
    def clean(self, js_code: str) -> dict:
        """
        Clean and normalize JavaScript code.
        
        Args:
            js_code: Raw JavaScript code string
            
        Returns:
            Dictionary with cleaned code and metadata
        """
        if not js_code or not isinstance(js_code, str):
            return {
                'cleaned_code': '',
                'original_length': 0,
                'cleaned_length': 0,
                'removed_comments': 0,
                'is_empty': True
            }
        
        original_length = len(js_code)
        
        # Step 1: Remove HTML/script tags if present
        js_code = self._remove_html_tags(js_code)
        
        # Step 2: Count and remove comments
        comment_count = self._count_comments(js_code)
        js_code = self._remove_comments(js_code)
        
        # Step 3: Normalize whitespace
        js_code = self._normalize_whitespace(js_code)
        
        # Step 4: Try to beautify (helps with minified code)
        try:
            js_code = jsbeautifier.beautify(js_code, self.beautifier_options)
        except:
            pass  # Keep original if beautify fails
        
        # Step 5: Remove empty lines
        js_code = self._remove_empty_lines(js_code)
        
        cleaned_length = len(js_code)
        
        return {
            'cleaned_code': js_code,
            'original_length': original_length,
            'cleaned_length': cleaned_length,
            'removed_comments': comment_count,
            'is_empty': len(js_code.strip()) == 0
        }
    
    def _remove_html_tags(self, code: str) -> str:
        """Remove HTML script tags."""
        # Remove <script> tags
        code = re.sub(r'<script[^>]*>', '', code, flags=re.IGNORECASE)
        code = re.sub(r'</script>', '', code, flags=re.IGNORECASE)
        return code
    
    def _count_comments(self, code: str) -> int:
        """Count number of comments."""
        # Single-line comments
        single_line = len(re.findall(r'//.*?$', code, re.MULTILINE))
        # Multi-line comments
        multi_line = len(re.findall(r'/\*.*?\*/', code, re.DOTALL))
        return single_line + multi_line
    
    def _remove_comments(self, code: str) -> str:
        """Remove JavaScript comments."""
        # Remove multi-line comments /* ... */
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # Remove single-line comments //
        code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
        return code
    
    def _normalize_whitespace(self, code: str) -> str:
        """Normalize whitespace but preserve structure."""
        # Replace multiple spaces with single space
        code = re.sub(r'[ \t]+', ' ', code)
        return code
    
    def _remove_empty_lines(self, code: str) -> str:
        """Remove empty lines."""
        lines = [line for line in code.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    def extract_strings(self, js_code: str) -> list:
        """
        Extract string literals from JavaScript code.
        
        Args:
            js_code: JavaScript code
            
        Returns:
            List of string literals
        """
        strings = []
        
        # Single-quoted strings
        strings.extend(re.findall(r"'([^'\\]*(?:\\.[^'\\]*)*)'", js_code))
        
        # Double-quoted strings
        strings.extend(re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', js_code))
        
        # Template literals
        strings.extend(re.findall(r'`([^`\\]*(?:\\.[^`\\]*)*)`', js_code))
        
        return strings
    
    def detect_encoding(self, string: str) -> dict:
        """
        Detect encoding types in string.
        
        Args:
            string: String to analyze
            
        Returns:
            Dictionary with encoding detection results
        """
        return {
            'is_base64': self._is_base64(string),
            'is_hex': self._is_hex(string),
            'is_unicode_escape': self._is_unicode_escape(string),
            'has_high_entropy': self._has_high_entropy(string)
        }
    
    def _is_base64(self, string: str) -> bool:
        """Check if string is base64 encoded."""
        if len(string) < 4:
            return False
        # Base64 pattern
        pattern = r'^[A-Za-z0-9+/]+=*$'
        return bool(re.match(pattern, string)) and len(string) % 4 == 0
    
    def _is_hex(self, string: str) -> bool:
        """Check if string is hex encoded."""
        if len(string) < 2:
            return False
        # Hex pattern (with or without 0x prefix)
        if string.startswith('0x') or string.startswith('\\x'):
            string = string[2:]
        pattern = r'^[0-9a-fA-F]+$'
        return bool(re.match(pattern, string))
    
    def _is_unicode_escape(self, string: str) -> bool:
        """Check if string contains unicode escapes."""
        return '\\u' in string or '\\x' in string
    
    def _has_high_entropy(self, string: str, threshold: float = 4.0) -> bool:
        """Check if string has high entropy (random-looking)."""
        if len(string) < 10:
            return False
        
        # Calculate Shannon entropy
        import math
        entropy = 0.0
        for x in range(256):
            p_x = float(string.count(chr(x))) / len(string)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy > threshold


if __name__ == "__main__":
    # Test the cleaner
    cleaner = JSCleaner()
    
    test_code = """
    <script>
    // This is a comment
    function test() {
        /* Multi-line
           comment */
        var x = "test";
        eval("malicious code");
    }
    </script>
    """
    
    result = cleaner.clean(test_code)
    print("Cleaning Test:")
    print(f"  Original length: {result['original_length']}")
    print(f"  Cleaned length: {result['cleaned_length']}")
    print(f"  Comments removed: {result['removed_comments']}")
    print(f"\nCleaned code:\n{result['cleaned_code']}")
    
    # Test string extraction
    strings = cleaner.extract_strings(result['cleaned_code'])
    print(f"\nExtracted strings: {strings}")
    
    # Test encoding detection
    test_strings = [
        "SGVsbG8gV29ybGQ=",  # Base64
        "48656c6c6f",  # Hex
        "Normal string",
        "\\u0048\\u0065\\u006c\\u006c\\u006f"  # Unicode
    ]
    
    print("\nEncoding Detection:")
    for s in test_strings:
        encoding = cleaner.detect_encoding(s)
        print(f"  '{s[:30]}...': {encoding}")
