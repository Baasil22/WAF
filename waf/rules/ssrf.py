"""
SSRF (Server-Side Request Forgery) Detection
Detects attempts to make the server request internal/external resources
"""
import re
from typing import Dict, Any, Optional, Tuple
import ipaddress


class SSRFDetector:
    """Detects Server-Side Request Forgery attacks"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile SSRF detection patterns"""
        
        # Internal IP patterns
        self.internal_patterns = [
            r'127\.\d+\.\d+\.\d+',           # Localhost
            r'10\.\d+\.\d+\.\d+',            # Private Class A
            r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',  # Private Class B
            r'192\.168\.\d+\.\d+',           # Private Class C
            r'169\.254\.\d+\.\d+',           # Link-local
            r'0\.0\.0\.0',                    # All interfaces
            r'\[?::1\]?',                     # IPv6 localhost
            r'\[?fe80:',                      # IPv6 link-local
            r'\[?fc00:',                      # IPv6 private
            r'\[?fd00:',                      # IPv6 private
        ]
        
        # Cloud metadata endpoints
        self.metadata_patterns = [
            r'169\.254\.169\.254',           # AWS/GCP/Azure metadata
            r'metadata\.google\.internal',    # GCP metadata
            r'metadata\.azure\.com',          # Azure metadata
            r'100\.100\.100\.200',           # Alibaba Cloud metadata
            r'192\.0\.0\.192',               # Oracle Cloud metadata
        ]
        
        # Dangerous protocols/schemes
        self.dangerous_schemes = [
            r'^file://',                      # Local file access
            r'^gopher://',                    # Gopher protocol
            r'^dict://',                      # Dict protocol
            r'^ftp://',                       # FTP
            r'^sftp://',                      # SFTP
            r'^ldap://',                      # LDAP
            r'^tftp://',                      # TFTP
            r'^jar://',                       # Java archive
            r'^netdoc://',                    # Netdoc
        ]
        
        # Bypass techniques
        self.bypass_patterns = [
            r'0x[0-9a-fA-F]+\.',             # Hex IP notation
            r'\d{8,}',                        # Decimal IP notation
            r'@',                             # @ in URL (credential bypass)
            r'#',                             # Fragment bypass
            r'localhost',                     # Localhost keyword
            r'localtest\.me',                 # DNS pointing to localhost
            r'spoofed\.',                     # Common spoofing domains
            r'xip\.io',                       # Wildcard DNS
            r'nip\.io',                       # Wildcard DNS
            r'burpcollaborator',              # Burp collaborator
            r'oastify\.com',                  # Interactsh
        ]
        
        self.compiled_internal = [re.compile(p, re.IGNORECASE) for p in self.internal_patterns]
        self.compiled_metadata = [re.compile(p, re.IGNORECASE) for p in self.metadata_patterns]
        self.compiled_schemes = [re.compile(p, re.IGNORECASE) for p in self.dangerous_schemes]
        self.compiled_bypass = [re.compile(p, re.IGNORECASE) for p in self.bypass_patterns]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect SSRF attack patterns
        
        Returns:
            Tuple of (is_attack, details)
        """
        # Check all URL-like parameters
        values_to_check = []
        
        # Query parameters
        for key, value in request_data.get('query_params', {}).items():
            if isinstance(value, str) and self._looks_like_url(key, value):
                values_to_check.append((f'query_{key}', value))
        
        # Body parameters
        body_params = request_data.get('body_params', {})
        for key, value in body_params.items():
            if isinstance(value, str) and self._looks_like_url(key, value):
                values_to_check.append((f'body_{key}', value))
        
        # Check each URL-like value
        for field, value in values_to_check:
            # Check for cloud metadata endpoints (highest priority)
            for pattern in self.compiled_metadata:
                if pattern.search(value):
                    return True, {
                        'attack_type': 'SSRF',
                        'severity': 'critical',
                        'pattern': 'Cloud metadata access',
                        'field': field,
                        'matched': value[:100]
                    }
            
            # Check for internal IPs
            for pattern in self.compiled_internal:
                if pattern.search(value):
                    return True, {
                        'attack_type': 'SSRF',
                        'severity': 'high',
                        'pattern': 'Internal IP access',
                        'field': field,
                        'matched': value[:100]
                    }
            
            # Check for dangerous schemes
            for pattern in self.compiled_schemes:
                if pattern.search(value):
                    return True, {
                        'attack_type': 'SSRF',
                        'severity': 'high',
                        'pattern': 'Dangerous protocol',
                        'field': field,
                        'matched': value[:100]
                    }
            
            # Check for bypass techniques (medium/high levels)
            if self.security_level in ['high', 'paranoid']:
                for pattern in self.compiled_bypass:
                    if pattern.search(value):
                        return True, {
                            'attack_type': 'SSRF',
                            'severity': 'medium',
                            'pattern': 'SSRF bypass attempt',
                            'field': field,
                            'matched': value[:100]
                        }
        
        return False, None
    
    def _looks_like_url(self, key: str, value: str) -> bool:
        """Check if a parameter looks like it could contain a URL"""
        url_param_names = [
            'url', 'uri', 'path', 'link', 'href', 'src', 'source',
            'redirect', 'target', 'dest', 'destination', 'rurl',
            'return', 'return_url', 'callback', 'next', 'ref',
            'feed', 'host', 'site', 'domain', 'proxy', 'img',
            'image', 'file', 'document', 'page', 'load', 'fetch'
        ]
        
        key_lower = key.lower()
        if any(name in key_lower for name in url_param_names):
            return True
        
        # Check if value looks like a URL
        url_indicators = ['http://', 'https://', '://', 'www.', '.com', '.org', '.net']
        return any(ind in value.lower() for ind in url_indicators)
