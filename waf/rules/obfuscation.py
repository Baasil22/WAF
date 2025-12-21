"""
Payload Obfuscation Detection
Detects attempts to bypass WAF using encoding and obfuscation
"""
import re
from typing import Dict, Any, Optional, Tuple


class ObfuscationDetector:
    """Detects payload obfuscation and encoding bypass attempts"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile obfuscation detection patterns"""
        
        self.patterns = {
            'critical': [
                # Double encoding
                r'%25[0-9a-fA-F]{2}',              # Double URL encoding
                r'%u[0-9a-fA-F]{4}',               # Unicode encoding
                r'\\x[0-9a-fA-F]{2}',              # Hex encoding
                r'\\u[0-9a-fA-F]{4}',              # Unicode escape
                
                # Null byte injection
                r'%00',                             # URL encoded null
                r'\\0',                             # Escaped null
                
                # Overlong UTF-8 encoding
                r'%c0%[89ab][0-9a-f]',             # 2-byte overlong
                r'%e0%80%[89ab][0-9a-f]',          # 3-byte overlong
                
                # Base64 encoded payloads
                r'(?:eval|exec|system)\s*\(\s*base64_decode',
                r'atob\s*\(',
            ],
            'high': [
                # HTML entity encoding
                r'&(?:#[xX]?[0-9a-fA-F]+|[a-zA-Z]+);',
                
                # Case manipulation with encoding
                r'(?:%[46][01])+',                 # Encoded case changes
                
                # Concatenation tricks
                r'\+\s*[\'"][^\'"]+[\'"]\s*\+',   # String concatenation
                r'\'\s*\+\s*\'',                   # Empty concatenation
                r'\"\s*\+\s*\"',
                
                # Comment injection
                r'/\*[^*]*\*/',                    # SQL/JS comments mid-payload
                
                # Unicode normalization attacks
                r'[\uff00-\uffef]',                # Fullwidth characters
            ],
            'medium': [
                # Mixed encoding
                r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}', # Multiple encoded chars
                
                # Whitespace manipulation
                r'\s{5,}',                         # Excessive whitespace
                r'[\t\r\n]+',                      # Tab/newline injection
                
                # Character insertion
                r'\w[\x00-\x08]\w',                # Control chars in words
            ],
            'low': [
                r'\\',                             # Any backslash
                r'%[0-9a-fA-F]{2}',               # Any URL encoding
            ]
        }
        
        self.compiled_patterns = {}
        for level, patterns in self.patterns.items():
            self.compiled_patterns[level] = [
                (re.compile(p, re.IGNORECASE), p) for p in patterns
            ]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect obfuscation attempts
        
        Returns:
            Tuple of (is_attack, details)
        """
        levels_to_check = self._get_levels_to_check()
        
        # Check query parameters
        for key, value in request_data.get('query_params', {}).items():
            if isinstance(value, str):
                result = self._check_value(value, f'query_{key}', levels_to_check)
                if result:
                    return True, result
        
        # Check body
        body = request_data.get('body', '')
        if isinstance(body, str):
            result = self._check_value(body, 'body', levels_to_check)
            if result:
                return True, result
        
        # Check path
        path = request_data.get('path', '')
        result = self._check_value(path, 'path', levels_to_check)
        if result:
            return True, result
        
        # Check headers
        for header, value in request_data.get('headers', {}).items():
            if isinstance(value, str):
                result = self._check_value(value, f'header_{header}', levels_to_check)
                if result:
                    return True, result
        
        return False, None
    
    def _get_levels_to_check(self) -> list:
        """Get security levels to check based on current setting"""
        level_map = {
            'low': ['critical'],
            'medium': ['critical', 'high'],
            'high': ['critical', 'high', 'medium'],
            'paranoid': ['critical', 'high', 'medium', 'low']
        }
        return level_map.get(self.security_level, ['critical', 'high'])
    
    def _check_value(self, value: str, field: str, levels: list) -> Optional[Dict[str, Any]]:
        """Check a single value for obfuscation patterns"""
        
        # Check for excessive encoding percentage
        if self._has_excessive_encoding(value):
            return {
                'attack_type': 'Payload Obfuscation',
                'severity': 'high',
                'pattern': 'Excessive encoding detected',
                'field': field,
                'matched': value[:100]
            }
        
        # Check specific patterns
        for level in levels:
            for pattern, pattern_str in self.compiled_patterns.get(level, []):
                match = pattern.search(value)
                if match:
                    return {
                        'attack_type': 'Payload Obfuscation',
                        'severity': level,
                        'pattern': pattern_str,
                        'field': field,
                        'matched': match.group(0)[:100]
                    }
        
        return None
    
    def _has_excessive_encoding(self, value: str) -> bool:
        """Check if value has excessive URL encoding"""
        if not value:
            return False
        
        # Count encoded characters
        encoded_count = len(re.findall(r'%[0-9a-fA-F]{2}', value))
        
        # If more than 30% of the value is encoded, it's suspicious
        threshold = 0.2 if self.security_level in ['high', 'paranoid'] else 0.3
        if len(value) > 10 and encoded_count / len(value) > threshold:
            return True
        
        return False
