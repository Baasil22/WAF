"""
Open Redirect Detection
Detects URL redirection attacks
"""
import re
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse


class OpenRedirectDetector:
    """Detects Open Redirect vulnerabilities"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile redirect detection patterns"""
        
        # Parameters commonly used for redirects
        self.redirect_params = [
            'url', 'redirect', 'redirect_url', 'redirect_uri', 'return',
            'return_url', 'returnto', 'redir', 'destination', 'dest',
            'next', 'target', 'to', 'goto', 'link', 'forward', 'forward_url',
            'continue', 'callback', 'path', 'out', 'view', 'site', 'ref'
        ]
        
        # Dangerous redirect patterns
        self.patterns = {
            'critical': [
                r'^//[^/]',                          # Protocol-relative URL
                r'^/\\',                             # Backslash after slash
                r'^\\\\',                            # UNC path
                r'javascript:',                      # JavaScript protocol
                r'data:',                            # Data URI
                r'vbscript:',                        # VBScript
                r'@',                                # URL with @ (redirect bypass)
            ],
            'high': [
                r'^https?://(?!localhost)',          # External URL
                r'^/\/[^/]',                         # Path confusion
                r'%2f%2f',                           # URL-encoded //
                r'%5c',                              # URL-encoded backslash
                r'%09',                              # Tab character
                r'%0a',                              # Newline
                r'%0d',                              # Carriage return
            ],
            'medium': [
                r'\.\./',                            # Directory traversal in URL
                r'^[a-z]+:',                         # Any protocol
            ],
            'low': [
                r'^http',                            # Any HTTP URL
            ]
        }
        
        self.compiled_patterns = {}
        for level, patterns in self.patterns.items():
            self.compiled_patterns[level] = [
                (re.compile(p, re.IGNORECASE), p) for p in patterns
            ]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect open redirect attacks
        
        Returns:
            Tuple of (is_attack, details)
        """
        levels_to_check = self._get_levels_to_check()
        host = request_data.get('headers', {}).get('Host', '')
        
        # Check query parameters
        for key, value in request_data.get('query_params', {}).items():
            if isinstance(value, str) and self._is_redirect_param(key):
                result = self._check_redirect(value, f'query_{key}', levels_to_check, host)
                if result:
                    return True, result
        
        # Check body parameters
        for key, value in request_data.get('body_params', {}).items():
            if isinstance(value, str) and self._is_redirect_param(key):
                result = self._check_redirect(value, f'body_{key}', levels_to_check, host)
                if result:
                    return True, result
        
        # Check Location header in responses (if available)
        headers = request_data.get('headers', {})
        if 'Location' in headers:
            result = self._check_redirect(headers['Location'], 'header_location', levels_to_check, host)
            if result:
                return True, result
        
        return False, None
    
    def _is_redirect_param(self, param_name: str) -> bool:
        """Check if parameter name suggests redirection"""
        param_lower = param_name.lower()
        return any(rp == param_lower or rp in param_lower for rp in self.redirect_params)
    
    def _check_redirect(self, value: str, field: str, levels: list, host: str) -> Optional[Dict[str, Any]]:
        """Check a redirect URL for malicious patterns"""
        
        # Check for dangerous patterns
        for level in levels:
            for pattern, pattern_str in self.compiled_patterns.get(level, []):
                if pattern.search(value):
                    return {
                        'attack_type': 'Open Redirect',
                        'severity': level,
                        'pattern': pattern_str,
                        'field': field,
                        'matched': value[:100]
                    }
        
        # Additional checks for external domains
        if self.security_level in ['high', 'paranoid']:
            if self._is_external_redirect(value, host):
                return {
                    'attack_type': 'Open Redirect',
                    'severity': 'medium',
                    'pattern': 'External domain redirect',
                    'field': field,
                    'matched': value[:100]
                }
        
        return None
    
    def _is_external_redirect(self, url: str, host: str) -> bool:
        """Check if URL redirects to external domain"""
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                # Has a domain specified
                return parsed.netloc.lower() != host.lower()
        except:
            pass
        return False
    
    def _get_levels_to_check(self) -> list:
        """Get security levels to check based on current setting"""
        level_map = {
            'low': ['critical'],
            'medium': ['critical', 'high'],
            'high': ['critical', 'high', 'medium'],
            'paranoid': ['critical', 'high', 'medium', 'low']
        }
        return level_map.get(self.security_level, ['critical', 'high'])
