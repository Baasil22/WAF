"""
Protocol Violation Detection
Detects HTTP protocol violations and anomalies
"""
import re
from typing import Dict, Any, Optional, Tuple


class ProtocolViolationDetector:
    """Detects HTTP protocol violations and anomalies"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect protocol violations
        
        Returns:
            Tuple of (is_attack, details)
        """
        headers = request_data.get('headers', {})
        method = request_data.get('method', '').upper()
        path = request_data.get('path', '')
        
        # Check for invalid HTTP methods
        valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
        if method and method not in valid_methods:
            return True, {
                'attack_type': 'Protocol Violation',
                'severity': 'high',
                'pattern': 'Invalid HTTP method',
                'field': 'method',
                'matched': method
            }
        
        # Block dangerous methods on high security
        if self.security_level in ['high', 'paranoid']:
            dangerous_methods = ['TRACE', 'TRACK', 'CONNECT']
            if method in dangerous_methods:
                return True, {
                    'attack_type': 'Protocol Violation',
                    'severity': 'medium',
                    'pattern': 'Dangerous HTTP method',
                    'field': 'method',
                    'matched': method
                }
        
        # Check for HTTP request smuggling patterns
        if self._check_request_smuggling(headers):
            return True, {
                'attack_type': 'Request Smuggling',
                'severity': 'critical',
                'pattern': 'Conflicting Content-Length/Transfer-Encoding',
                'field': 'headers',
                'matched': 'Multiple content descriptors'
            }
        
        # Check for abnormal header values
        result = self._check_abnormal_headers(headers)
        if result:
            return True, result
        
        # Check for path anomalies
        result = self._check_path_anomalies(path)
        if result:
            return True, result
        
        return False, None
    
    def _check_request_smuggling(self, headers: Dict) -> bool:
        """Check for HTTP request smuggling indicators"""
        content_length = headers.get('Content-Length', '')
        transfer_encoding = headers.get('Transfer-Encoding', '')
        
        # Both headers present (potential CL.TE or TE.CL attack)
        if content_length and transfer_encoding:
            return True
        
        # Check for obfuscated Transfer-Encoding
        for header, value in headers.items():
            if 'transfer' in header.lower() and 'encoding' in header.lower():
                if header != 'Transfer-Encoding':  # Obfuscated
                    return True
        
        return False
    
    def _check_abnormal_headers(self, headers: Dict) -> Optional[Dict[str, Any]]:
        """Check for abnormal header patterns"""
        
        # Check for overly long headers
        max_header_length = 4096 if self.security_level == 'paranoid' else 8192
        for header, value in headers.items():
            if isinstance(value, str) and len(value) > max_header_length:
                return {
                    'attack_type': 'Protocol Violation',
                    'severity': 'medium',
                    'pattern': 'Oversized header value',
                    'field': f'header_{header}',
                    'matched': f'{header}: {len(value)} bytes'
                }
        
        # Check for null bytes in headers
        for header, value in headers.items():
            if isinstance(value, str) and ('\x00' in value or '%00' in value):
                return {
                    'attack_type': 'Protocol Violation',
                    'severity': 'high',
                    'pattern': 'Null byte in header',
                    'field': f'header_{header}',
                    'matched': f'{header}'
                }
        
        # Check for non-ASCII characters in Host header
        host = headers.get('Host', '')
        if host and not all(ord(c) < 128 for c in host):
            return {
                'attack_type': 'Protocol Violation',
                'severity': 'high',
                'pattern': 'Non-ASCII Host header',
                'field': 'header_host',
                'matched': host[:50]
            }
        
        return None
    
    def _check_path_anomalies(self, path: str) -> Optional[Dict[str, Any]]:
        """Check for URL path anomalies"""
        
        # Check for double URL encoding
        if '%25' in path:
            return {
                'attack_type': 'Protocol Violation',
                'severity': 'high',
                'pattern': 'Double URL encoding',
                'field': 'path',
                'matched': path[:100]
            }
        
        # Check for path containing control characters
        if re.search(r'[\x00-\x1f\x7f]', path):
            return {
                'attack_type': 'Protocol Violation',
                'severity': 'high',
                'pattern': 'Control characters in path',
                'field': 'path',
                'matched': path[:100]
            }
        
        # Check for excessively long paths
        max_path_length = 2048 if self.security_level in ['high', 'paranoid'] else 4096
        if len(path) > max_path_length:
            return {
                'attack_type': 'Protocol Violation',
                'severity': 'medium',
                'pattern': 'Oversized URL path',
                'field': 'path',
                'matched': f'{len(path)} bytes'
            }
        
        return None
