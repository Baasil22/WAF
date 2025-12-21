"""
WAF Middleware
Core middleware that intercepts and analyzes all HTTP requests
"""
import time
import json
import os
from datetime import datetime
from typing import Tuple, Optional
from threading import Lock
from flask import request, Response

# Core detectors
from .rules.sql_injection import SQLInjectionDetector
from .rules.xss import XSSDetector
from .rules.path_traversal import PathTraversalDetector
from .rules.command_injection import CommandInjectionDetector

# Advanced detectors
from .rules.csrf import CSRFDetector
from .rules.crlf import CRLFDetector
from .rules.ssrf import SSRFDetector
from .rules.ssti import SSTIDetector
from .rules.xxe import XXEDetector
from .rules.file_inclusion import FileInclusionDetector
from .rules.bot_detection import BotDetector
from .rules.auth_attack import AuthAttackDetector
from .rules.open_redirect import OpenRedirectDetector
from .rules.protocol_violation import ProtocolViolationDetector
from .rules.obfuscation import ObfuscationDetector
from .rules.deserialization import DeserializationDetector

from .rate_limiter import RateLimiter
from .ip_filter import IPFilter

class WAFMiddleware:
    """Web Application Firewall Middleware"""
    
    def __init__(self, app=None, config=None):
        """
        Initialize WAF middleware
        
        Args:
            app: Flask application instance
            config: Configuration object
        """
        self.app = app
        self.config = config
        
        # Initialize detectors
        security_level = getattr(config, 'SECURITY_LEVEL', 'medium') if config else 'medium'
        
        # Core detectors
        self.sql_detector = SQLInjectionDetector(security_level)
        self.xss_detector = XSSDetector(security_level)
        self.path_detector = PathTraversalDetector(security_level)
        self.cmd_detector = CommandInjectionDetector(security_level)
        
        # Advanced detectors
        self.csrf_detector = CSRFDetector(security_level)
        self.crlf_detector = CRLFDetector(security_level)
        self.ssrf_detector = SSRFDetector(security_level)
        self.ssti_detector = SSTIDetector(security_level)
        self.xxe_detector = XXEDetector(security_level)
        self.file_inclusion_detector = FileInclusionDetector(security_level)
        self.bot_detector = BotDetector(security_level)
        self.auth_detector = AuthAttackDetector(security_level)
        self.redirect_detector = OpenRedirectDetector(security_level)
        self.protocol_detector = ProtocolViolationDetector(security_level)
        self.obfuscation_detector = ObfuscationDetector(security_level)
        self.deserialization_detector = DeserializationDetector(security_level)
        
        # Initialize rate limiter
        self.rate_limiter = RateLimiter(
            max_requests=getattr(config, 'RATE_LIMIT_REQUESTS', 100) if config else 100,
            window_seconds=getattr(config, 'RATE_LIMIT_WINDOW', 60) if config else 60,
            ban_duration=getattr(config, 'RATE_LIMIT_BAN_DURATION', 300) if config else 300
        )
        
        # Initialize IP filter
        data_dir = getattr(config, 'DATA_DIR', 'data') if config else 'data'
        self.ip_filter = IPFilter(os.path.join(data_dir, 'blocked_ips.json'))
        
        # Attack logs
        self.logs = []
        self.logs_file = os.path.join(data_dir, 'attack_logs.json')
        self.lock = Lock()
        self._load_logs()
        
        # Statistics - extended for new attack types
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'sql_injection_blocked': 0,
            'xss_blocked': 0,
            'path_traversal_blocked': 0,
            'command_injection_blocked': 0,
            'csrf_blocked': 0,
            'crlf_blocked': 0,
            'ssrf_blocked': 0,
            'ssti_blocked': 0,
            'xxe_blocked': 0,
            'lfi_rfi_blocked': 0,
            'bot_blocked': 0,
            'auth_attack_blocked': 0,
            'open_redirect_blocked': 0,
            'protocol_violation_blocked': 0,
            'obfuscation_blocked': 0,
            'deserialization_blocked': 0,
            'rate_limited': 0,
            'ip_blocked': 0,
            'start_time': time.time()
        }
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app
        app.before_request(self.before_request)
    
    def _load_logs(self):
        """Load attack logs from file"""
        if os.path.exists(self.logs_file):
            try:
                with open(self.logs_file, 'r') as f:
                    self.logs = json.load(f)
            except:
                self.logs = []
    
    def _save_logs(self):
        """Save attack logs to file"""
        os.makedirs(os.path.dirname(self.logs_file), exist_ok=True)
        try:
            with open(self.logs_file, 'w') as f:
                # Keep only last 1000 logs
                json.dump(self.logs[-1000:], f, indent=2)
        except:
            pass
    
    def _get_client_ip(self) -> str:
        """Get real client IP address"""
        # Check for proxy headers
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        return request.remote_addr or '127.0.0.1'
    
    def _get_request_data(self) -> dict:
        """Extract all data from request"""
        data = {}
        
        # Query parameters
        for key, value in request.args.items():
            data[f'query_{key}'] = value
        
        # Form data
        for key, value in request.form.items():
            data[f'form_{key}'] = value
        
        # JSON body
        if request.is_json:
            try:
                json_data = request.get_json()
                if isinstance(json_data, dict):
                    for key, value in json_data.items():
                        data[f'json_{key}'] = str(value)
            except:
                pass
        
        # Headers that might contain payloads
        for header in ['User-Agent', 'Referer', 'Cookie', 'Origin']:
            if request.headers.get(header):
                data[f'header_{header}'] = request.headers.get(header)
        
        # URL path
        data['path'] = request.path
        
        # Raw body (if not form or json)
        if request.data and not request.form and not request.is_json:
            try:
                data['body'] = request.data.decode('utf-8', errors='ignore')
            except:
                pass
        
        return data
    
    def _log_attack(self, ip: str, attack_info: dict, request_info: dict):
        """Log detected attack"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'attack_type': attack_info.get('type', 'Unknown'),
            'severity': attack_info.get('severity', 'medium'),
            'pattern': attack_info.get('pattern', ''),
            'matched': attack_info.get('matched', ''),
            'field': attack_info.get('field', ''),
            'method': request_info.get('method', ''),
            'path': request_info.get('path', ''),
            'user_agent': request_info.get('user_agent', '')
        }
        
        with self.lock:
            self.logs.append(log_entry)
            self._save_logs()
    
    def _create_block_response(self, attack_info: dict) -> Response:
        """Create blocked request response"""
        response_data = {
            'status': 'blocked',
            'message': 'Request blocked by WAF',
            'reason': attack_info.get('type', 'Security violation'),
            'request_id': f"WAF-{int(time.time())}"
        }
        
        return Response(
            json.dumps(response_data),
            status=403,
            mimetype='application/json',
            headers={
                'X-WAF-Block': 'true',
                'X-WAF-Reason': attack_info.get('type', 'Security violation')
            }
        )
    
    def before_request(self):
        """Process request before it reaches the application"""
        # Skip WAF for dashboard, auth, and all dashboard management API routes
        # NOTE: /api/test and /api/echo are NOT skipped - they are protected by WAF
        
        # Routes to skip completely (exact match)
        skip_exact = ['/', '/login', '/logout']
        
        # Routes to skip with prefix matching
        skip_prefix = [
            '/dashboard',  # All dashboard pages
            '/static',     # Static files
            '/api/stats',  # Stats API
            '/api/logs',   # Logs API
            '/api/ip',     # IP management API
            '/api/ratelimit',  # Rate limit API
            '/api/config'  # Config API
        ]
        
        # Check exact matches
        if request.path in skip_exact:
            return None
        
        # Check prefix matches
        for prefix in skip_prefix:
            if request.path.startswith(prefix):
                return None
        
        self.stats['total_requests'] += 1
        
        client_ip = self._get_client_ip()
        request_data = self._get_request_data()
        
        request_info = {
            'method': request.method,
            'path': request.path,
            'user_agent': request.headers.get('User-Agent', '')
        }
        
        # 1. Check IP filter (blacklist/whitelist)
        is_allowed, ip_info = self.ip_filter.check_ip(client_ip)
        if not is_allowed:
            self.stats['blocked_requests'] += 1
            self.stats['ip_blocked'] += 1
            self._log_attack(client_ip, ip_info, request_info)
            return self._create_block_response(ip_info)
        
        # 2. Check rate limit
        is_allowed, rate_info = self.rate_limiter.check_rate_limit(client_ip)
        if not is_allowed:
            self.stats['blocked_requests'] += 1
            self.stats['rate_limited'] += 1
            self._log_attack(client_ip, rate_info, request_info)
            return self._create_block_response(rate_info)
        
        # 3. Check for SQL Injection
        is_attack, sql_info = self.sql_detector.analyze_request(request_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['sql_injection_blocked'] += 1
            self._log_attack(client_ip, sql_info, request_info)
            return self._create_block_response(sql_info)
        
        # 4. Check for XSS
        is_attack, xss_info = self.xss_detector.analyze_request(request_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['xss_blocked'] += 1
            self._log_attack(client_ip, xss_info, request_info)
            return self._create_block_response(xss_info)
        
        # 5. Check for Path Traversal
        is_attack, path_info = self.path_detector.analyze_request(request_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['path_traversal_blocked'] += 1
            self._log_attack(client_ip, path_info, request_info)
            return self._create_block_response(path_info)
        
        # 6. Check for Command Injection
        is_attack, cmd_info = self.cmd_detector.analyze_request(request_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['command_injection_blocked'] += 1
            self._log_attack(client_ip, cmd_info, request_info)
            return self._create_block_response(cmd_info)
        
        # Prepare extended request data for new detectors
        extended_data = {
            'method': request.method,
            'path': request.path,
            'ip': client_ip,
            'query_params': dict(request.args),
            'body_params': dict(request.form),
            'body': request.data.decode('utf-8', errors='ignore') if request.data else '',
            'headers': dict(request.headers),
            'cookies': dict(request.cookies),
            'files': {}
        }
        
        # 7. Check for CRLF Injection
        is_attack, crlf_info = self.crlf_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['crlf_blocked'] += 1
            crlf_info['type'] = crlf_info.get('attack_type', 'CRLF Injection')
            self._log_attack(client_ip, crlf_info, request_info)
            return self._create_block_response(crlf_info)
        
        # 8. Check for SSRF
        is_attack, ssrf_info = self.ssrf_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['ssrf_blocked'] += 1
            ssrf_info['type'] = ssrf_info.get('attack_type', 'SSRF')
            self._log_attack(client_ip, ssrf_info, request_info)
            return self._create_block_response(ssrf_info)
        
        # 9. Check for SSTI
        is_attack, ssti_info = self.ssti_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['ssti_blocked'] += 1
            ssti_info['type'] = ssti_info.get('attack_type', 'SSTI')
            self._log_attack(client_ip, ssti_info, request_info)
            return self._create_block_response(ssti_info)
        
        # 10. Check for XXE
        is_attack, xxe_info = self.xxe_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['xxe_blocked'] += 1
            xxe_info['type'] = xxe_info.get('attack_type', 'XXE')
            self._log_attack(client_ip, xxe_info, request_info)
            return self._create_block_response(xxe_info)
        
        # 11. Check for LFI/RFI
        is_attack, lfi_info = self.file_inclusion_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['lfi_rfi_blocked'] += 1
            lfi_info['type'] = lfi_info.get('attack_type', 'File Inclusion')
            self._log_attack(client_ip, lfi_info, request_info)
            return self._create_block_response(lfi_info)
        
        # 12. Check for Bot activity
        is_attack, bot_info = self.bot_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['bot_blocked'] += 1
            bot_info['type'] = bot_info.get('attack_type', 'Bot Detection')
            self._log_attack(client_ip, bot_info, request_info)
            return self._create_block_response(bot_info)
        
        # 13. Check for Authentication attacks
        is_attack, auth_info = self.auth_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['auth_attack_blocked'] += 1
            auth_info['type'] = auth_info.get('attack_type', 'Auth Attack')
            self._log_attack(client_ip, auth_info, request_info)
            return self._create_block_response(auth_info)
        
        # 14. Check for Open Redirect
        is_attack, redirect_info = self.redirect_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['open_redirect_blocked'] += 1
            redirect_info['type'] = redirect_info.get('attack_type', 'Open Redirect')
            self._log_attack(client_ip, redirect_info, request_info)
            return self._create_block_response(redirect_info)
        
        # 15. Check for Protocol Violations
        is_attack, protocol_info = self.protocol_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['protocol_violation_blocked'] += 1
            protocol_info['type'] = protocol_info.get('attack_type', 'Protocol Violation')
            self._log_attack(client_ip, protocol_info, request_info)
            return self._create_block_response(protocol_info)
        
        # 16. Check for Payload Obfuscation
        is_attack, obf_info = self.obfuscation_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['obfuscation_blocked'] += 1
            obf_info['type'] = obf_info.get('attack_type', 'Payload Obfuscation')
            self._log_attack(client_ip, obf_info, request_info)
            return self._create_block_response(obf_info)
        
        # 17. Check for Insecure Deserialization
        is_attack, deser_info = self.deserialization_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['deserialization_blocked'] += 1
            deser_info['type'] = deser_info.get('attack_type', 'Insecure Deserialization')
            self._log_attack(client_ip, deser_info, request_info)
            return self._create_block_response(deser_info)
        
        # 18. Check for CSRF (only on state-changing requests)
        is_attack, csrf_info = self.csrf_detector.detect(extended_data)
        if is_attack:
            self.stats['blocked_requests'] += 1
            self.stats['csrf_blocked'] += 1
            csrf_info['type'] = csrf_info.get('attack_type', 'CSRF')
            self._log_attack(client_ip, csrf_info, request_info)
            return self._create_block_response(csrf_info)
        
        # Request is clean
        return None
    
    def get_stats(self) -> dict:
        """Get WAF statistics"""
        uptime = time.time() - self.stats['start_time']
        return {
            **self.stats,
            'uptime_seconds': int(uptime),
            'uptime_formatted': self._format_uptime(uptime),
            'block_rate': round(
                (self.stats['blocked_requests'] / max(self.stats['total_requests'], 1)) * 100, 2
            )
        }
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format"""
        hours, remainder = divmod(int(seconds), 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    
    def get_logs(self, limit: int = 100) -> list:
        """Get recent attack logs"""
        with self.lock:
            return self.logs[-limit:][::-1]  # Return newest first
    
    def clear_logs(self):
        """Clear all attack logs"""
        with self.lock:
            self.logs = []
            self._save_logs()
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'sql_injection_blocked': 0,
            'xss_blocked': 0,
            'path_traversal_blocked': 0,
            'command_injection_blocked': 0,
            'rate_limited': 0,
            'ip_blocked': 0,
            'start_time': time.time()
        }
