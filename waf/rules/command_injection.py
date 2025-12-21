"""
Command Injection Detection Module
Detects OS command injection attacks
"""
import re
from typing import Tuple, Optional

class CommandInjectionDetector:
    """Detects Command Injection attacks"""
    
    PATTERNS = {
        'critical': [
            # Command chaining
            r"(?i);\s*(cat|ls|dir|rm|del|wget|curl|nc|netcat|bash|sh|cmd|powershell)",
            r"(?i)\|\s*(cat|ls|dir|rm|del|wget|curl|nc|netcat|bash|sh|cmd|powershell)",
            r"(?i)&&\s*(cat|ls|dir|rm|del|wget|curl|nc|netcat|bash|sh|cmd|powershell)",
            r"(?i)\|\|\s*(cat|ls|dir|rm|del|wget|curl|nc|netcat|bash|sh|cmd|powershell)",
            # Backtick execution
            r"`[^`]+`",
            # $() execution
            r"\$\([^)]+\)",
            # Direct dangerous commands
            r"(?i)(rm|del)\s+(-rf?|/[sq])?\s*[/\\]",
            r"(?i)(wget|curl)\s+[^\s]+\s*\|",
        ],
        'high': [
            # Shell command indicators
            r"(?i)/bin/(sh|bash|csh|ksh|zsh)",
            r"(?i)cmd\.exe",
            r"(?i)powershell\.exe",
            r"(?i)/dev/(null|tcp|udp)",
            # Command separators
            r";\s*\w+",
            r"\|\s*\w+",
            r"&&\s*\w+",
            r"\|\|\s*\w+",
            # Redirection
            r">\s*[/\\]?\w+",
            r"2>&1",
            r"<\s*[/\\]?\w+",
        ],
        'medium': [
            # Common exploit commands
            r"(?i)(cat|type|more)\s+[/\\]",
            r"(?i)(whoami|id|uname|hostname)",
            r"(?i)(netstat|ifconfig|ipconfig|nslookup)",
            r"(?i)(ping|traceroute|tracert)\s+",
            # Encoded characters
            r"%0[ad]",  # URL encoded newline/carriage return
            r"%3b",     # URL encoded semicolon
            r"%7c",     # URL encoded pipe
        ],
        'low': [
            r"(?i)(echo|print)\s+",
            r"(?i)(set|export)\s+\w+=",
        ]
    }
    
    def __init__(self, security_level: str = 'medium'):
        """Initialize command injection detector"""
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
        """Check if data contains command injection patterns"""
        if not data:
            return False, None
        
        for compiled_pattern, severity, pattern in self.compiled_patterns:
            match = compiled_pattern.search(data)
            if match:
                return True, {
                    'type': 'Command Injection',
                    'severity': severity,
                    'pattern': pattern,
                    'matched': match.group(),
                    'position': match.span()
                }
        
        return False, None
    
    def analyze_request(self, request_data: dict) -> Tuple[bool, Optional[dict]]:
        """Analyze entire request for command injection attacks"""
        # Skip User-Agent header - it often contains semicolons like "; Win64" which are normal
        skip_fields = ['header_User-Agent', 'header_Cookie']
        
        for key, value in request_data.items():
            # Skip known safe fields that may contain semicolons
            if key in skip_fields:
                continue
            if isinstance(value, str):
                is_attack, info = self.detect(value)
                if is_attack:
                    info['field'] = key
                    return True, info
        
        return False, None
