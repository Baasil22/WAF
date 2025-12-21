"""
HTTP Header Injection (CRLF) Detection
Detects carriage return line feed injection attacks
"""
import re
from typing import Dict, Any, Optional, Tuple


class CRLFDetector:
    """Detects HTTP Header Injection (CRLF) attacks"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile CRLF injection patterns"""
        
        # CRLF injection patterns
        self.patterns = {
            'critical': [
                r'%0[dD]%0[aA]',              # URL-encoded CRLF
                r'%0[aA]%0[dD]',              # Reversed
                r'\r\n',                       # Raw CRLF
                r'%0[dD]',                     # CR only
                r'%0[aA]',                     # LF only
                r'\\r\\n',                     # Escaped CRLF
                r'\x0d\x0a',                   # Hex CRLF
                r'%u000[dD]%u000[aA]',        # Unicode encoded
            ],
            'high': [
                r'%c0%8d%c0%8a',              # Overlong UTF-8
                r'%e5%98%8a%e5%98%8d',        # UTF-8 encoding bypass
                r'Set-Cookie:',               # Cookie injection
                r'Location:',                 # Redirect injection
                r'Content-Type:',             # Content-Type injection
                r'X-[A-Za-z-]+:',             # Custom header injection
            ],
            'medium': [
                r'HTTP/\d\.\d',               # HTTP protocol injection
                r'Content-Length:',           # Response splitting
                r'Transfer-Encoding:',        # Encoding manipulation
            ],
            'low': [
                r'<\s*script',                # XSS via header injection
                r'javascript:',               # JS via header
            ]
        }
        
        self.compiled_patterns = {}
        for level, patterns in self.patterns.items():
            self.compiled_patterns[level] = [
                (re.compile(p, re.IGNORECASE), p) for p in patterns
            ]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect CRLF injection attacks
        
        Returns:
            Tuple of (is_attack, details)
        """
        levels_to_check = self._get_levels_to_check()
        
        # Check headers for CRLF in values
        headers = request_data.get('headers', {})
        for header_name, header_value in headers.items():
            if isinstance(header_value, str):
                result = self._check_value(header_value, f'header_{header_name}', levels_to_check)
                if result:
                    return True, result
        
        # Check query parameters
        query_params = request_data.get('query_params', {})
        for param_name, param_value in query_params.items():
            if isinstance(param_value, str):
                result = self._check_value(param_value, f'query_{param_name}', levels_to_check)
                if result:
                    return True, result
        
        # Check path
        path = request_data.get('path', '')
        result = self._check_value(path, 'path', levels_to_check)
        if result:
            return True, result
        
        # Check body
        body = request_data.get('body', '')
        if isinstance(body, str):
            result = self._check_value(body, 'body', levels_to_check)
            if result:
                return True, result
        
        return False, None
    
    def _get_levels_to_check(self) -> list:
        """Get security levels to check based on current setting"""
        level_order = ['critical', 'high', 'medium', 'low']
        level_map = {
            'low': ['critical'],
            'medium': ['critical', 'high'],
            'high': ['critical', 'high', 'medium'],
            'paranoid': ['critical', 'high', 'medium', 'low']
        }
        return level_map.get(self.security_level, ['critical', 'high'])
    
    def _check_value(self, value: str, field: str, levels: list) -> Optional[Dict[str, Any]]:
        """Check a single value for CRLF patterns"""
        for level in levels:
            for pattern, pattern_str in self.compiled_patterns.get(level, []):
                if pattern.search(value):
                    return {
                        'attack_type': 'CRLF Injection',
                        'severity': level,
                        'pattern': pattern_str,
                        'field': field,
                        'matched': value[:100]
                    }
        return None
