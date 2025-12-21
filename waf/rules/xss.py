"""
XSS (Cross-Site Scripting) Detection Module
Detects common XSS attack patterns
"""
import re
import html
from typing import Tuple, Optional

class XSSDetector:
    """Detects Cross-Site Scripting (XSS) attacks"""
    
    PATTERNS = {
        'critical': [
            # Script tags
            r"(?i)<script[^>]*>.*?</script>",
            r"(?i)<script[^>]*>",
            r"(?i)</script>",
            # JavaScript protocol
            r"(?i)javascript\s*:",
            r"(?i)vbscript\s*:",
            r"(?i)data\s*:.*?base64",
            # Direct execution
            r"(?i)eval\s*\(",
            r"(?i)expression\s*\(",
            r"(?i)document\s*\.\s*(cookie|write|location)",
            r"(?i)window\s*\.\s*location",
        ],
        'high': [
            # Event handlers
            r"(?i)on(load|error|click|mouse|focus|blur|change|submit|key|drag|drop)\s*=",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)onclick\s*=",
            r"(?i)onmouseover\s*=",
            r"(?i)onfocus\s*=",
            r"(?i)onblur\s*=",
            # Dangerous tags
            r"(?i)<iframe[^>]*>",
            r"(?i)<object[^>]*>",
            r"(?i)<embed[^>]*>",
            r"(?i)<form[^>]*>",
            r"(?i)<input[^>]*>",
            r"(?i)<svg[^>]*onload",
            r"(?i)<img[^>]*onerror",
            r"(?i)<body[^>]*onload",
        ],
        'medium': [
            # HTML injection
            r"(?i)<[a-z].*?>",
            r"(?i)</[a-z]+>",
            # Style-based attacks
            r"(?i)style\s*=\s*[\"'][^\"']*expression",
            r"(?i)style\s*=\s*[\"'][^\"']*url\s*\(",
            r"(?i)-moz-binding",
            # Encoded payloads
            r"(?i)&#x?[0-9a-f]+;",
            r"(?i)%3c.*?%3e",  # URL encoded tags
            r"(?i)\\x3c.*?\\x3e",  # Hex encoded
            r"(?i)\\u003c.*?\\u003e",  # Unicode encoded
        ],
        'low': [
            # Potential indicators
            r"(?i)alert\s*\(",
            r"(?i)confirm\s*\(",
            r"(?i)prompt\s*\(",
            r"(?i)console\s*\.",
        ]
    }
    
    def __init__(self, security_level: str = 'medium'):
        """Initialize XSS detector with security level"""
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
    
    def _decode_payload(self, data: str) -> list:
        """Decode various encoded payloads"""
        decoded_versions = [data]
        
        # HTML entity decode
        try:
            html_decoded = html.unescape(data)
            if html_decoded != data:
                decoded_versions.append(html_decoded)
        except:
            pass
        
        # URL decode
        try:
            from urllib.parse import unquote
            url_decoded = unquote(data)
            if url_decoded != data:
                decoded_versions.append(url_decoded)
        except:
            pass
        
        return decoded_versions
    
    def detect(self, data: str) -> Tuple[bool, Optional[dict]]:
        """
        Check if data contains XSS patterns
        
        Args:
            data: String data to analyze
            
        Returns:
            Tuple of (is_attack, attack_info)
        """
        if not data:
            return False, None
        
        # Check original and decoded versions
        for decoded_data in self._decode_payload(data):
            for compiled_pattern, severity, pattern in self.compiled_patterns:
                match = compiled_pattern.search(decoded_data)
                if match:
                    return True, {
                        'type': 'XSS',
                        'severity': severity,
                        'pattern': pattern,
                        'matched': match.group(),
                        'position': match.span()
                    }
        
        return False, None
    
    def analyze_request(self, request_data: dict) -> Tuple[bool, Optional[dict]]:
        """Analyze entire request for XSS attacks"""
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
    
    def sanitize(self, data: str) -> str:
        """Sanitize input by encoding dangerous characters"""
        return html.escape(data)
