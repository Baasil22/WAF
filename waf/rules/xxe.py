"""
XXE (XML External Entity) Detection
Detects XML-based attacks including external entity injection
"""
import re
from typing import Dict, Any, Optional, Tuple


class XXEDetector:
    """Detects XML External Entity attacks"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile XXE detection patterns"""
        
        self.patterns = {
            'critical': [
                # DOCTYPE with ENTITY
                r'<!DOCTYPE[^>]*\[',                  # DOCTYPE with internal subset
                r'<!ENTITY\s+\w+\s+SYSTEM',          # External entity
                r'<!ENTITY\s+\w+\s+PUBLIC',          # Public entity
                r'<!ENTITY\s+%\s*\w+',               # Parameter entity
                
                # Common XXE payloads
                r'file://',                           # Local file access
                r'expect://',                         # PHP expect
                r'php://filter',                      # PHP filter
                r'php://input',                       # PHP input
                r'data://text',                       # Data URI
                r'compress\.zlib://',                 # Compression wrappers
                
                # Entity references
                r'&\w+;',                             # Named entity reference
                r'&#x?[0-9a-fA-F]+;',                # Numeric entity reference
            ],
            'high': [
                # External DTD references
                r'<!DOCTYPE[^>]*SYSTEM',              # External DTD
                r'<!DOCTYPE[^>]*PUBLIC',              # Public DTD
                
                # XInclude
                r'<xi:include',                       # XInclude element
                r'xmlns:xi=',                         # XInclude namespace
                
                # SSRF via XXE
                r'http://localhost',                  # Localhost access
                r'http://127\.',                      # Loopback
                r'http://192\.168\.',                 # Private IP
                r'http://10\.',                       # Private IP
                r'http://172\.(1[6-9]|2|3[01])\.',   # Private IP
                
                # Common targets
                r'/etc/passwd',                       # Unix passwd
                r'/etc/shadow',                       # Unix shadow
                r'/etc/hosts',                        # Hosts file
                r'c:\\windows',                       # Windows directory
            ],
            'medium': [
                # XML declarations that might indicate XXE setup
                r'<\?xml[^>]*encoding',              # XML encoding
                r'<\?xml[^>]*standalone\s*=\s*["\']no', # Standalone no
                
                # CDATA abuse
                r'<!\[CDATA\[',                      # CDATA section
                
                # Billion laughs DoS
                r'<!ENTITY\s+\w+\s+["\'][^"\']*&\w+;', # Entity expansion
            ],
            'low': [
                r'<!DOCTYPE',                         # Any DOCTYPE
                r'<!ENTITY',                          # Any ENTITY
                r'<\?xml',                            # XML declaration
            ]
        }
        
        self.compiled_patterns = {}
        for level, patterns in self.patterns.items():
            self.compiled_patterns[level] = [
                (re.compile(p, re.IGNORECASE), p) for p in patterns
            ]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect XXE attack patterns
        
        Returns:
            Tuple of (is_attack, details)
        """
        levels_to_check = self._get_levels_to_check()
        content_type = request_data.get('headers', {}).get('Content-Type', '')
        
        # Focus on XML content types
        is_xml = 'xml' in content_type.lower()
        
        # Check body (primary target for XXE)
        body = request_data.get('body', '')
        if isinstance(body, str):
            result = self._check_value(body, 'body', levels_to_check, is_xml)
            if result:
                return True, result
        
        # Check query parameters
        for key, value in request_data.get('query_params', {}).items():
            if isinstance(value, str):
                result = self._check_value(value, f'query_{key}', levels_to_check, False)
                if result:
                    return True, result
        
        # Check file uploads for XML content
        files = request_data.get('files', {})
        for filename, content in files.items():
            if isinstance(content, str) and (filename.endswith('.xml') or 'xml' in filename.lower()):
                result = self._check_value(content, f'file_{filename}', levels_to_check, True)
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
    
    def _check_value(self, value: str, field: str, levels: list, is_xml: bool) -> Optional[Dict[str, Any]]:
        """Check a single value for XXE patterns"""
        for level in levels:
            # For XML content, check all levels; otherwise only critical/high
            if not is_xml and level in ['medium', 'low']:
                continue
                
            for pattern, pattern_str in self.compiled_patterns.get(level, []):
                match = pattern.search(value)
                if match:
                    return {
                        'attack_type': 'XXE',
                        'severity': level,
                        'pattern': pattern_str,
                        'field': field,
                        'matched': match.group(0)[:100]
                    }
        return None
