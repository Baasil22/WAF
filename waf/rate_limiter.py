"""
Rate Limiter Module
Prevents brute-force and DDoS attacks by limiting request rates
"""
import time
from collections import defaultdict
from typing import Tuple, Optional
from threading import Lock

class RateLimiter:
    """Rate limiter using sliding window algorithm"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60, ban_duration: int = 300):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Maximum requests allowed per window
            window_seconds: Time window in seconds
            ban_duration: Ban duration in seconds when limit exceeded
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.ban_duration = ban_duration
        
        # Store request timestamps per IP
        self.requests = defaultdict(list)
        # Store banned IPs with expiry time
        self.banned_ips = {}
        # Thread safety
        self.lock = Lock()
    
    def _cleanup_old_requests(self, ip: str, current_time: float):
        """Remove requests outside the current window"""
        cutoff_time = current_time - self.window_seconds
        self.requests[ip] = [
            ts for ts in self.requests[ip] 
            if ts > cutoff_time
        ]
    
    def _cleanup_expired_bans(self, current_time: float):
        """Remove expired bans"""
        expired = [
            ip for ip, expiry in self.banned_ips.items() 
            if expiry < current_time
        ]
        for ip in expired:
            del self.banned_ips[ip]
    
    def is_banned(self, ip: str) -> bool:
        """Check if an IP is currently banned"""
        current_time = time.time()
        
        with self.lock:
            self._cleanup_expired_bans(current_time)
            return ip in self.banned_ips
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, Optional[dict]]:
        """
        Check if request should be allowed based on rate limit
        
        Args:
            ip: Client IP address
            
        Returns:
            Tuple of (is_allowed, info)
        """
        current_time = time.time()
        
        with self.lock:
            # Check if IP is banned
            if ip in self.banned_ips:
                remaining_ban = int(self.banned_ips[ip] - current_time)
                if remaining_ban > 0:
                    return False, {
                        'reason': 'IP is temporarily banned',
                        'remaining_seconds': remaining_ban,
                        'type': 'Rate Limit Ban'
                    }
                else:
                    del self.banned_ips[ip]
            
            # Clean up old requests
            self._cleanup_old_requests(ip, current_time)
            
            # Check request count
            request_count = len(self.requests[ip])
            
            if request_count >= self.max_requests:
                # Ban the IP
                self.banned_ips[ip] = current_time + self.ban_duration
                return False, {
                    'reason': f'Rate limit exceeded: {request_count}/{self.max_requests} requests',
                    'ban_duration': self.ban_duration,
                    'type': 'Rate Limit Exceeded'
                }
            
            # Record this request
            self.requests[ip].append(current_time)
            
            return True, {
                'requests_made': request_count + 1,
                'requests_remaining': self.max_requests - request_count - 1,
                'window_seconds': self.window_seconds
            }
    
    def get_stats(self, ip: str) -> dict:
        """Get rate limit stats for an IP"""
        current_time = time.time()
        
        with self.lock:
            self._cleanup_old_requests(ip, current_time)
            
            request_count = len(self.requests[ip])
            is_banned = ip in self.banned_ips
            
            return {
                'ip': ip,
                'requests_in_window': request_count,
                'max_requests': self.max_requests,
                'window_seconds': self.window_seconds,
                'is_banned': is_banned,
                'ban_expires': self.banned_ips.get(ip, None)
            }
    
    def ban_ip(self, ip: str, duration: int = None):
        """Manually ban an IP"""
        duration = duration or self.ban_duration
        with self.lock:
            self.banned_ips[ip] = time.time() + duration
    
    def unban_ip(self, ip: str):
        """Manually unban an IP"""
        with self.lock:
            if ip in self.banned_ips:
                del self.banned_ips[ip]
    
    def get_all_banned(self) -> dict:
        """Get all currently banned IPs"""
        current_time = time.time()
        
        with self.lock:
            self._cleanup_expired_bans(current_time)
            return {
                ip: int(expiry - current_time) 
                for ip, expiry in self.banned_ips.items()
            }
    
    def reset_ip(self, ip: str):
        """Reset rate limit counter for an IP"""
        with self.lock:
            if ip in self.requests:
                del self.requests[ip]
            if ip in self.banned_ips:
                del self.banned_ips[ip]
