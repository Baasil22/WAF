"""
CSRF (Cross-Site Request Forgery) Detection
Detects attempts to forge requests from untrusted origins
"""
import re
from typing import Dict, Any, Optional, Tuple


class CSRFDetector:
    """Detects Cross-Site Request Forgery attacks"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile detection patterns based on security level"""
        
        # Suspicious referrer patterns
        self.suspicious_referrers = [
            r'javascript:',
            r'data:',
            r'file:',
            r'about:blank',
        ]
        
        # Content types that might indicate CSRF
        self.suspicious_content_types = [
            'text/plain',
            'application/x-www-form-urlencoded',
            'multipart/form-data'
        ]
        
        # State-changing HTTP methods
        self.state_changing_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
        
        self.compiled_referrers = [re.compile(p, re.IGNORECASE) for p in self.suspicious_referrers]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect CSRF attack patterns
        
        Returns:
            Tuple of (is_attack, details)
        """
        method = request_data.get('method', 'GET').upper()
        headers = request_data.get('headers', {})
        
        # Only check state-changing methods
        if method not in self.state_changing_methods:
            return False, None
        
        origin = headers.get('Origin', '')
        referer = headers.get('Referer', '')
        host = headers.get('Host', '')
        content_type = headers.get('Content-Type', '')
        
        # Check for missing Origin on state-changing requests (high security)
        if self.security_level in ['high', 'paranoid']:
            if not origin and not referer:
                return True, {
                    'attack_type': 'CSRF',
                    'severity': 'medium',
                    'pattern': 'Missing Origin/Referer header',
                    'field': 'headers',
                    'matched': 'No origin tracking'
                }
        
        # Check for suspicious referrer patterns
        for pattern in self.compiled_referrers:
            if pattern.search(referer):
                return True, {
                    'attack_type': 'CSRF',
                    'severity': 'high',
                    'pattern': pattern.pattern,
                    'field': 'referer',
                    'matched': referer[:100]
                }
        
        # Check for cross-origin requests without proper headers
        if origin and host:
            if not self._is_same_origin(origin, host):
                # Check if it's a simple request (potential CSRF)
                if self._is_simple_request(content_type, headers):
                    return True, {
                        'attack_type': 'CSRF',
                        'severity': 'high',
                        'pattern': 'Cross-origin simple request',
                        'field': 'origin',
                        'matched': f'Origin: {origin}, Host: {host}'
                    }
        
        return False, None
    
    def _is_same_origin(self, origin: str, host: str) -> bool:
        """Check if origin matches host"""
        # Extract domain from origin (remove protocol)
        origin_domain = re.sub(r'^https?://', '', origin).split('/')[0]
        return origin_domain == host or host in origin_domain
    
    def _is_simple_request(self, content_type: str, headers: Dict) -> bool:
        """Check if request is a 'simple' CORS request (potential CSRF)"""
        simple_content_types = [
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain'
        ]
        return any(ct in content_type.lower() for ct in simple_content_types)
