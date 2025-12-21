"""
SQL Injection Detection Module
Detects common SQL injection attack patterns
"""
import re
from typing import Tuple, Optional

class SQLInjectionDetector:
    """Detects SQL Injection attacks in request data"""
    
    # SQL Injection patterns organized by severity
    PATTERNS = {
        'critical': [
            # UNION-based injection
            r"(?i)union\s+(all\s+)?select",
            r"(?i)union\s+select\s+null",
            # Time-based blind injection
            r"(?i)sleep\s*\(\s*\d+\s*\)",
            r"(?i)benchmark\s*\(",
            r"(?i)waitfor\s+delay",
            r"(?i)pg_sleep",
            # Stacked queries
            r";\s*(drop|delete|truncate|update|insert)\s+",
            # Direct table access
            r"(?i)into\s+(out|dump)file",
            r"(?i)load_file\s*\(",
        ],
        'high': [
            # Boolean-based injection
            r"(?i)'\s*(or|and)\s+['\d].*[=<>]",
            r"(?i)\"\s*(or|and)\s+[\"\\d].*[=<>]",
            r"(?i)'\s*or\s+1\s*=\s*1",
            r"(?i)'\s*or\s+'[^']*'\s*=\s*'",
            # Comment-based injection
            r"(?i)'\s*--",
            r"(?i)'\s*#",
            r"(?i)'\s*/\*",
            # Basic SQL commands with suspicious context
            r"(?i)'\s*;\s*(select|insert|update|delete|drop)",
        ],
        'medium': [
            # SQL keywords in suspicious patterns
            r"(?i)(select|insert|update|delete|drop|create|alter|truncate)\s+.*(from|into|table|database)",
            r"(?i)information_schema",
            r"(?i)sysobjects",
            r"(?i)syscolumns",
            # Encoded characters
            r"(?i)%27",  # URL encoded single quote
            r"(?i)%22",  # URL encoded double quote
            r"(?i)0x[0-9a-f]+",  # Hex values
            # Null byte injection
            r"\x00",
        ],
        'low': [
            # Single quotes in value context
            r"'[^']*'",
            r"--\s*$",
            r"#\s*$",
        ]
    }
    
    def __init__(self, security_level: str = 'medium'):
        """
        Initialize detector with security level
        
        Args:
            security_level: 'low', 'medium', 'high', or 'paranoid'
        """
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
        """
        Check if data contains SQL injection patterns
        
        Args:
            data: String data to analyze
            
        Returns:
            Tuple of (is_attack, attack_info)
        """
        if not data:
            return False, None
        
        for compiled_pattern, severity, pattern in self.compiled_patterns:
            match = compiled_pattern.search(data)
            if match:
                return True, {
                    'type': 'SQL Injection',
                    'severity': severity,
                    'pattern': pattern,
                    'matched': match.group(),
                    'position': match.span()
                }
        
        return False, None
    
    def analyze_request(self, request_data: dict) -> Tuple[bool, Optional[dict]]:
        """
        Analyze entire request for SQL injection
        
        Args:
            request_data: Dictionary containing request parameters
            
        Returns:
            Tuple of (is_attack, attack_info)
        """
        # Check all string values in the request
        for key, value in request_data.items():
            if isinstance(value, str):
                is_attack, info = self.detect(value)
                if is_attack:
                    info['field'] = key
                    return True, info
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        is_attack, info = self.detect(item)
                        if is_attack:
                            info['field'] = key
                            return True, info
        
        return False, None
