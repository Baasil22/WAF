"""
SSTI (Server-Side Template Injection) Detection
Detects attempts to inject template expressions
"""
import re
from typing import Dict, Any, Optional, Tuple


class SSTIDetector:
    """Detects Server-Side Template Injection attacks"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile SSTI detection patterns for various template engines"""
        
        self.patterns = {
            'critical': [
                # Jinja2/Twig/Django
                r'\{\{\s*[\w\s\.]+\s*\}\}',           # {{ expression }}
                r'\{%\s*[\w\s]+\s*%\}',               # {% statement %}
                r'\{\{\s*config',                      # {{ config }}
                r'\{\{\s*self\._',                     # {{ self._ }}
                r'\{\{\s*request\.',                   # {{ request. }}
                r'__class__',                          # Python class access
                r'__mro__',                            # Method Resolution Order
                r'__subclasses__',                     # Subclasses access
                r'__globals__',                        # Globals access
                r'__builtins__',                       # Builtins access
                
                # Ruby ERB
                r'<%=?\s*.*\s*%>',                    # <% code %> / <%= output %>
                
                # JavaScript template literals
                r'\$\{[^}]+\}',                       # ${expression}
                
                # Freemarker
                r'\$\{[^}]+\}',                       # ${expression}
                r'<#assign',                           # Variable assignment
                r'<#if',                              # Conditional
                r'\.getClass\(',                      # Java class access
            ],
            'high': [
                # Smarty
                r'\{\s*\$[\w\.]+\s*\}',               # {$variable}
                r'\{\s*php\s*\}',                     # {php} block
                
                # Mako
                r'\$\{[^}]+\}',                       # ${expression}
                r'<%\s*.*\s*%>',                      # <% code %>
                
                # Velocity
                r'#set\s*\(',                         # Variable setting
                r'\$\w+\.\w+',                        # $object.method
                
                # Pebble
                r'\{\{\s*[\w\.]+\s*\}\}',
                r'\{%\s*\w+',
                
                # Common payloads
                r'lipsum',                            # Jinja2 lipsum
                r'joiner',                            # Jinja2 joiner
                r'cycler',                            # Jinja2 cycler
            ],
            'medium': [
                # General patterns
                r'\[\s*[\'"]__\w+__[\'"]\s*\]',      # ['__dunder__']
                r'getattr\s*\(',                      # Python getattr
                r'eval\s*\(',                         # eval()
                r'exec\s*\(',                         # exec()
                r'compile\s*\(',                      # compile()
                r'import\s*\(',                       # __import__()
                r'open\s*\(',                         # open()
            ],
            'low': [
                r'\{\{',                              # Any {{ start
                r'\}\}',                              # Any }} end
                r'<%',                                # Any <% start
                r'%>',                                # Any %> end
            ]
        }
        
        self.compiled_patterns = {}
        for level, patterns in self.patterns.items():
            self.compiled_patterns[level] = [
                (re.compile(p, re.IGNORECASE), p) for p in patterns
            ]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect SSTI attack patterns
        
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
        
        # Check body parameters
        for key, value in request_data.get('body_params', {}).items():
            if isinstance(value, str):
                result = self._check_value(value, f'body_{key}', levels_to_check)
                if result:
                    return True, result
        
        # Check headers (user-agent, referer, etc.)
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
        """Check a single value for SSTI patterns"""
        for level in levels:
            for pattern, pattern_str in self.compiled_patterns.get(level, []):
                match = pattern.search(value)
                if match:
                    return {
                        'attack_type': 'SSTI',
                        'severity': level,
                        'pattern': pattern_str,
                        'field': field,
                        'matched': match.group(0)[:100]
                    }
        return None
