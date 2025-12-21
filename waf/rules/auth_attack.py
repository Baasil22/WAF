"""
Authentication Attack Detection
Detects brute force, credential stuffing, password spraying, and account enumeration
"""
import re
from typing import Dict, Any, Optional, Tuple
from collections import defaultdict
import time


class AuthAttackDetector:
    """Detects authentication-based attacks"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        
        # Tracking dictionaries
        self.failed_attempts = defaultdict(list)  # IP -> list of (timestamp, username)
        self.username_attempts = defaultdict(list)  # Username -> list of (timestamp, IP)
        
        # Configuration based on security level
        self.config = self._get_config()
    
    def _get_config(self) -> Dict:
        """Get configuration based on security level"""
        configs = {
            'low': {
                'max_attempts_per_ip': 20,
                'max_attempts_per_user': 15,
                'time_window': 300,  # 5 minutes
                'spray_threshold': 10,
            },
            'medium': {
                'max_attempts_per_ip': 10,
                'max_attempts_per_user': 8,
                'time_window': 300,
                'spray_threshold': 5,
            },
            'high': {
                'max_attempts_per_ip': 5,
                'max_attempts_per_user': 5,
                'time_window': 300,
                'spray_threshold': 3,
            },
            'paranoid': {
                'max_attempts_per_ip': 3,
                'max_attempts_per_user': 3,
                'time_window': 600,  # 10 minutes
                'spray_threshold': 2,
            }
        }
        return configs.get(self.security_level, configs['medium'])
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect authentication attacks
        
        Returns:
            Tuple of (is_attack, details)
        """
        path = request_data.get('path', '').lower()
        method = request_data.get('method', '').upper()
        
        # Only check POST requests to authentication endpoints
        auth_endpoints = [
            '/login', '/signin', '/auth', '/authenticate',
            '/api/login', '/api/auth', '/api/token',
            '/wp-login', '/admin/login', '/user/login',
            '/account/login', '/session/new'
        ]
        
        if method != 'POST' or not any(ep in path for ep in auth_endpoints):
            return False, None
        
        ip = request_data.get('ip', '')
        current_time = time.time()
        
        # Extract username from request
        body_params = request_data.get('body_params', {})
        username = body_params.get('username', body_params.get('email', body_params.get('user', '')))
        
        # Track this attempt
        self.failed_attempts[ip].append((current_time, username))
        if username:
            self.username_attempts[username].append((current_time, ip))
        
        # Clean old entries
        self._cleanup_old_entries(current_time)
        
        # Check for brute force (many attempts from same IP)
        recent_ip_attempts = [
            a for a in self.failed_attempts[ip]
            if current_time - a[0] < self.config['time_window']
        ]
        
        if len(recent_ip_attempts) > self.config['max_attempts_per_ip']:
            return True, {
                'attack_type': 'Brute Force',
                'severity': 'high',
                'pattern': f'{len(recent_ip_attempts)} login attempts from IP',
                'field': 'auth',
                'matched': f'IP: {ip}, Attempts: {len(recent_ip_attempts)}'
            }
        
        # Check for credential stuffing (many different usernames from same IP)
        if username:
            unique_usernames = set(a[1] for a in recent_ip_attempts if a[1])
            if len(unique_usernames) > self.config['spray_threshold']:
                return True, {
                    'attack_type': 'Credential Stuffing',
                    'severity': 'critical',
                    'pattern': f'{len(unique_usernames)} different usernames from same IP',
                    'field': 'auth',
                    'matched': f'IP: {ip}, Usernames: {len(unique_usernames)}'
                }
        
        # Check for password spraying (same password across many users)
        # This is detected when many IPs try the same user
        if username:
            recent_user_attempts = [
                a for a in self.username_attempts[username]
                if current_time - a[0] < self.config['time_window']
            ]
            unique_ips = set(a[1] for a in recent_user_attempts)
            
            if len(unique_ips) > self.config['spray_threshold']:
                return True, {
                    'attack_type': 'Password Spraying',
                    'severity': 'high',
                    'pattern': f'{len(unique_ips)} IPs targeting same user',
                    'field': 'auth',
                    'matched': f'Username: {username[:20]}, IPs: {len(unique_ips)}'
                }
        
        # Check for account enumeration patterns
        if self._check_enumeration_pattern(request_data, username):
            return True, {
                'attack_type': 'Account Enumeration',
                'severity': 'medium',
                'pattern': 'Sequential/predictable username pattern',
                'field': 'auth',
                'matched': f'Username pattern: {username[:20]}'
            }
        
        return False, None
    
    def _cleanup_old_entries(self, current_time: float):
        """Remove entries older than time window"""
        window = self.config['time_window']
        
        for ip in list(self.failed_attempts.keys()):
            self.failed_attempts[ip] = [
                a for a in self.failed_attempts[ip]
                if current_time - a[0] < window
            ]
            if not self.failed_attempts[ip]:
                del self.failed_attempts[ip]
        
        for user in list(self.username_attempts.keys()):
            self.username_attempts[user] = [
                a for a in self.username_attempts[user]
                if current_time - a[0] < window
            ]
            if not self.username_attempts[user]:
                del self.username_attempts[user]
    
    def _check_enumeration_pattern(self, request_data: Dict[str, Any], username: str) -> bool:
        """Check for account enumeration patterns"""
        if not username:
            return False
        
        # Check for sequential patterns (user1, user2, user3, etc.)
        sequential_pattern = re.compile(r'^(.*?)(\d+)$')
        match = sequential_pattern.match(username)
        
        if match:
            base_name = match.group(1)
            number = int(match.group(2))
            
            # Check if we've seen sequential usernames
            ip = request_data.get('ip', '')
            recent_attempts = self.failed_attempts.get(ip, [])
            
            sequential_count = 0
            for _, attempted_user in recent_attempts[-10:]:
                if attempted_user:
                    other_match = sequential_pattern.match(attempted_user)
                    if other_match and other_match.group(1) == base_name:
                        sequential_count += 1
            
            if sequential_count >= 3:
                return True
        
        return False
