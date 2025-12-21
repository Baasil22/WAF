"""
Insecure Deserialization Detection
Detects serialization-based attacks
"""
import re
from typing import Dict, Any, Optional, Tuple


class DeserializationDetector:
    """Detects insecure deserialization attacks"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile deserialization detection patterns"""
        
        self.patterns = {
            'critical': [
                # Java serialization
                r'rO0AB',                          # Base64 Java serialized
                r'aced0005',                       # Java magic bytes (hex)
                r'\\xac\\xed\\x00\\x05',          # Java magic bytes
                r'java\.lang\.Runtime',            # Runtime execution
                r'java\.io\.',                     # Java IO classes
                r'ProcessBuilder',                 # Process execution
                
                # PHP serialization
                r'O:\d+:"[^"]+":',                # PHP object serialization
                r'a:\d+:{',                        # PHP array serialization
                r's:\d+:"',                        # PHP string serialization
                r'__wakeup',                       # PHP magic method
                r'__destruct',                     # PHP magic method
                r'__call',                         # PHP magic method
                
                # Python pickle
                r'c__builtin__',                   # Python builtins
                r'cos\nsystem',                    # Pickle system call
                r'cposix\nsystem',                 # Pickle posix
                r'\\x80\\x03',                    # Pickle protocol 3
                r'\\x80\\x04',                    # Pickle protocol 4
                
                # .NET
                r'TypeConfuseDelegate',            # .NET gadget
                r'System\.Diagnostics\.Process',   # .NET process
                r'WindowsIdentity',                # .NET identity
            ],
            'high': [
                # Ruby Marshal
                r'\\x04\\x08',                    # Ruby marshal magic
                
                # Node.js
                r'node-serialize',                 # Node serialization
                r'_$$ND_FUNC$$_',                 # node-serialize function
                
                # YAML deserialization
                r'!!python/',                      # Python YAML tags
                r'!!ruby/',                        # Ruby YAML tags
                r'!ruby/object:',                  # Ruby object
                r'!ruby/hash:',                    # Ruby hash
                
                # JSON type confusion
                r'"__proto__"',                    # Prototype pollution
                r'"constructor"',                  # Constructor access
                r'"__lookupGetter__"',             # Getter access
            ],
            'medium': [
                # Generic serialization indicators
                r'serialize',
                r'unserialize',
                r'readObject',
                r'writeObject',
                r'Pickle',
                r'Marshal',
            ]
        }
        
        self.compiled_patterns = {}
        for level, patterns in self.patterns.items():
            self.compiled_patterns[level] = [
                (re.compile(p, re.IGNORECASE), p) for p in patterns
            ]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect insecure deserialization attacks
        
        Returns:
            Tuple of (is_attack, details)
        """
        levels_to_check = self._get_levels_to_check()
        content_type = request_data.get('headers', {}).get('Content-Type', '')
        
        # Check body (primary target)
        body = request_data.get('body', '')
        if isinstance(body, str):
            result = self._check_value(body, 'body', levels_to_check)
            if result:
                return True, result
        
        # Check cookies (common deserialization target)
        cookies = request_data.get('cookies', {})
        for name, value in cookies.items():
            if isinstance(value, str):
                result = self._check_value(value, f'cookie_{name}', levels_to_check)
                if result:
                    return True, result
        
        # Check query parameters
        for key, value in request_data.get('query_params', {}).items():
            if isinstance(value, str):
                result = self._check_value(value, f'query_{key}', levels_to_check)
                if result:
                    return True, result
        
        # Check headers that might contain serialized data
        for header in ['X-Session', 'X-Token', 'X-Data', 'Authorization']:
            value = request_data.get('headers', {}).get(header, '')
            if value:
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
            'paranoid': ['critical', 'high', 'medium']
        }
        return level_map.get(self.security_level, ['critical', 'high'])
    
    def _check_value(self, value: str, field: str, levels: list) -> Optional[Dict[str, Any]]:
        """Check a single value for deserialization patterns"""
        for level in levels:
            for pattern, pattern_str in self.compiled_patterns.get(level, []):
                match = pattern.search(value)
                if match:
                    return {
                        'attack_type': 'Insecure Deserialization',
                        'severity': level,
                        'pattern': pattern_str,
                        'field': field,
                        'matched': match.group(0)[:100]
                    }
        return None
