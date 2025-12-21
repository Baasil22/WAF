"""
LFI/RFI (Local/Remote File Inclusion) Detection
Enhanced file inclusion attack detection
"""
import re
from typing import Dict, Any, Optional, Tuple


class FileInclusionDetector:
    """Detects Local and Remote File Inclusion attacks"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile file inclusion detection patterns"""
        
        self.patterns = {
            'critical': [
                # Remote File Inclusion
                r'https?://',                         # HTTP/HTTPS URLs
                r'ftp://',                            # FTP URLs
                r'php://filter',                      # PHP filter wrapper
                r'php://input',                       # PHP input stream
                r'php://data',                        # PHP data wrapper
                r'data:text/plain',                   # Data URI
                r'data:text/html',                    # Data URI HTML
                r'expect://',                         # PHP expect wrapper
                r'zip://',                            # ZIP wrapper
                r'compress\.zlib://',                 # Zlib wrapper
                r'phar://',                           # PHAR wrapper
                
                # Null byte injection
                r'%00',                               # Null byte
                r'\x00',                              # Null byte hex
                
                # Critical files
                r'/etc/passwd',
                r'/etc/shadow',
                r'/etc/hosts',
                r'/proc/self',
                r'/var/log/',
                r'boot\.ini',
                r'win\.ini',
                r'system32',
            ],
            'high': [
                # Directory traversal variations
                r'\.\./\.\.',                        # Multiple ..
                r'\.\.\\\.\.\\',                     # Windows backslash
                r'\.\.%2f',                          # URL encoded /
                r'%2e%2e/',                          # URL encoded ..
                r'%2e%2e%2f',                        # Fully encoded ../
                r'\.\.%5c',                          # URL encoded backslash
                r'%252e%252e',                       # Double encoded
                r'\.\.%c0%af',                       # Overlong encoding
                r'\.\.%c1%9c',                       # Overlong backslash
                
                # Common config files
                r'\.htaccess',
                r'\.htpasswd',
                r'web\.config',
                r'\.git/',
                r'\.svn/',
                r'\.env',
                r'config\.php',
                r'database\.yml',
                r'settings\.py',
                r'wp-config\.php',
            ],
            'medium': [
                # Single directory traversal
                r'\.\./',                            # Basic traversal
                r'\.\.\\',                           # Windows traversal
                
                # Log files
                r'access\.log',
                r'error\.log',
                r'debug\.log',
                
                # Source code access
                r'\.php$',
                r'\.asp$',
                r'\.jsp$',
                r'\.py$',
            ],
            'low': [
                r'\.\.',                             # Any ..
                r'~/',                               # Home directory
                r'/tmp/',                            # Temp directory
            ]
        }
        
        self.compiled_patterns = {}
        for level, patterns in self.patterns.items():
            self.compiled_patterns[level] = [
                (re.compile(p, re.IGNORECASE), p) for p in patterns
            ]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect LFI/RFI attack patterns
        
        Returns:
            Tuple of (is_attack, details)
        """
        levels_to_check = self._get_levels_to_check()
        
        # Check path
        path = request_data.get('path', '')
        result = self._check_value(path, 'path', levels_to_check)
        if result:
            return True, result
        
        # Check query parameters (common target for file inclusion)
        for key, value in request_data.get('query_params', {}).items():
            if isinstance(value, str):
                # Prioritize file-related parameters
                if self._is_file_param(key):
                    result = self._check_value(value, f'query_{key}', levels_to_check, priority=True)
                else:
                    result = self._check_value(value, f'query_{key}', levels_to_check)
                if result:
                    return True, result
        
        # Check body parameters
        for key, value in request_data.get('body_params', {}).items():
            if isinstance(value, str):
                result = self._check_value(value, f'body_{key}', levels_to_check)
                if result:
                    return True, result
        
        return False, None
    
    def _is_file_param(self, param_name: str) -> bool:
        """Check if parameter name suggests file operations"""
        file_params = [
            'file', 'path', 'page', 'pagename', 'include', 'inc',
            'template', 'tmpl', 'load', 'lang', 'language', 'dir',
            'doc', 'document', 'folder', 'root', 'module', 'mod',
            'content', 'read', 'view', 'layout', 'style', 'theme'
        ]
        param_lower = param_name.lower()
        return any(fp in param_lower for fp in file_params)
    
    def _get_levels_to_check(self) -> list:
        """Get security levels to check based on current setting"""
        level_map = {
            'low': ['critical'],
            'medium': ['critical', 'high'],
            'high': ['critical', 'high', 'medium'],
            'paranoid': ['critical', 'high', 'medium', 'low']
        }
        return level_map.get(self.security_level, ['critical', 'high'])
    
    def _check_value(self, value: str, field: str, levels: list, priority: bool = False) -> Optional[Dict[str, Any]]:
        """Check a single value for file inclusion patterns"""
        for level in levels:
            for pattern, pattern_str in self.compiled_patterns.get(level, []):
                match = pattern.search(value)
                if match:
                    # Determine if it's LFI or RFI
                    attack_type = 'RFI' if 'http' in pattern_str.lower() or '://' in value else 'LFI'
                    return {
                        'attack_type': attack_type,
                        'severity': level,
                        'pattern': pattern_str,
                        'field': field,
                        'matched': match.group(0)[:100]
                    }
        return None
