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

from .rules.sql_injection import SQLInjectionDetector
from .rules.xss import XSSDetector
from .rules.path_traversal import PathTraversalDetector
from .rules.command_injection import CommandInjectionDetector
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
        
        self.sql_detector = SQLInjectionDetector(security_level)
        self.xss_detector = XSSDetector(security_level)
        self.path_detector = PathTraversalDetector(security_level)
        self.cmd_detector = CommandInjectionDetector(security_level)
        
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
        
        # Statistics
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
