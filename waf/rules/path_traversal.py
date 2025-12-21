"""
Path Traversal Detection Module
Detects directory traversal and file inclusion attacks
"""
import re
from typing import Tuple, Optional

class PathTraversalDetector:
    """Detects Path Traversal and Local File Inclusion attacks"""
    
    PATTERNS = {
        'critical': [
            # Direct path traversal
            r"(?i)\.\./\.\./\.\./",
            r"(?i)\.\.\\\.\.\\\.\.\\",
            # System file access
            r"(?i)/etc/passwd",
            r"(?i)/etc/shadow",
            r"(?i)/etc/hosts",
            r"(?i)c:\\windows\\system32",
            r"(?i)c:\\boot\.ini",
            r"(?i)/proc/self",
            # PHP wrappers
            r"(?i)php://filter",
            r"(?i)php://input",
            r"(?i)expect://",
            r"(?i)data://",
        ],
        'high': [
            # Basic traversal
            r"(?i)\.\./",
            r"(?i)\.\.\\",
            # Encoded traversal
            r"(?i)%2e%2e[%2f/\\]",
            r"(?i)%252e%252e",
            r"(?i)\.\.%2f",
            r"(?i)\.\.%5c",
            # Null byte injection
            r"(?i)%00",
            r"\x00",
            # Common target files
            r"(?i)/var/log",
            r"(?i)/var/www",
            r"(?i)web\.config",
            r"(?i)\.htaccess",
            r"(?i)\.htpasswd",
        ],
        'medium': [
            # File extensions often targeted
            r"(?i)\.(ini|conf|config|cfg|xml)(\?|#|$)",
            r"(?i)\.(bak|backup|old|orig)(\?|#|$)",
            r"(?i)\.(sql|log|txt)(\?|#|$)",
            # Absolute path indicators
            r"(?i)^/[a-z]+/",
            r"(?i)^[a-z]:\\",
        ],
        'low': [
            r"(?i)file://",
            r"(?i)\.env",
        ]
    }
    
    def __init__(self, security_level: str = 'medium'):
        """Initialize path traversal detector"""
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns based on security level"""
        levels = ['critical', 'high', 'medium', 'low']
        level_index = {
            'paranoid': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        
        active_levels = levels[:level_index.get(self.security_level, 2)]
        
        self.compiled_patterns = []
        for level in active_levels:
            for pattern in self.PATTERNS.get(level, []):
                try:
                    self.compiled_patterns.append((
                        re.compile(pattern),
                        level,
                        pattern
                    ))
                except re.error:
                    pass
    
    def detect(self, data: str) -> Tuple[bool, Optional[dict]]:
        """Check if data contains path traversal patterns"""
        if not data:
            return False, None
        
        for compiled_pattern, severity, pattern in self.compiled_patterns:
            match = compiled_pattern.search(data)
            if match:
                return True, {
                    'type': 'Path Traversal',
                    'severity': severity,
                    'pattern': pattern,
                    'matched': match.group(),
                    'position': match.span()
                }
        
        return False, None
    
    def analyze_request(self, request_data: dict) -> Tuple[bool, Optional[dict]]:
        """Analyze entire request for path traversal attacks"""
        for key, value in request_data.items():
            if isinstance(value, str):
                is_attack, info = self.detect(value)
                if is_attack:
                    info['field'] = key
                    return True, info
        
        return False, None
