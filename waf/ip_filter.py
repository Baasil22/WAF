"""
IP Filter Module
Manages IP whitelisting, blacklisting, and geo-blocking
"""
import json
import os
import ipaddress
from typing import Tuple, Optional, List
from threading import Lock

class IPFilter:
    """IP filtering with whitelist/blacklist support"""
    
    def __init__(self, data_file: str = None):
        """
        Initialize IP filter
        
        Args:
            data_file: Path to JSON file for persistent storage
        """
        self.data_file = data_file
        self.whitelist = set()
        self.blacklist = set()
        self.whitelist_ranges = []  # CIDR ranges
        self.blacklist_ranges = []  # CIDR ranges
        self.lock = Lock()
        
        if data_file:
            self._load_data()
    
    def _load_data(self):
        """Load IP lists from file"""
        if not os.path.exists(self.data_file):
            return
        
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
                self.whitelist = set(data.get('whitelist', []))
                self.blacklist = set(data.get('blacklist', []))
                
                # Parse CIDR ranges
                for cidr in data.get('whitelist_ranges', []):
                    try:
                        self.whitelist_ranges.append(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        pass
                
                for cidr in data.get('blacklist_ranges', []):
                    try:
                        self.blacklist_ranges.append(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        pass
        except (json.JSONDecodeError, IOError):
            pass
    
    def _save_data(self):
        """Save IP lists to file"""
        if not self.data_file:
            return
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
        
        data = {
            'whitelist': list(self.whitelist),
            'blacklist': list(self.blacklist),
            'whitelist_ranges': [str(r) for r in self.whitelist_ranges],
            'blacklist_ranges': [str(r) for r in self.blacklist_ranges]
        }
        
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _ip_in_ranges(self, ip: str, ranges: List) -> bool:
        """Check if IP is in any of the CIDR ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in ranges:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        return False
    
    def check_ip(self, ip: str) -> Tuple[bool, Optional[dict]]:
        """
        Check if IP is allowed
        
        Args:
            ip: IP address to check
            
        Returns:
            Tuple of (is_allowed, info)
        """
        with self.lock:
            # Check whitelist first (whitelist takes priority)
            if ip in self.whitelist or self._ip_in_ranges(ip, self.whitelist_ranges):
                return True, {
                    'status': 'whitelisted',
                    'ip': ip
                }
            
            # Check blacklist
            if ip in self.blacklist or self._ip_in_ranges(ip, self.blacklist_ranges):
                return False, {
                    'status': 'blacklisted',
                    'ip': ip,
                    'type': 'IP Blacklisted'
                }
            
            # Default: allow
            return True, {
                'status': 'allowed',
                'ip': ip
            }
    
    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist"""
        with self.lock:
            # Check if it's a CIDR range
            if '/' in ip:
                try:
                    network = ipaddress.ip_network(ip, strict=False)
                    if network not in self.whitelist_ranges:
                        self.whitelist_ranges.append(network)
                except ValueError:
                    return False
            else:
                self.whitelist.add(ip)
            
            # Remove from blacklist if present
            self.blacklist.discard(ip)
            
            self._save_data()
            return True
    
    def add_to_blacklist(self, ip: str, reason: str = None):
        """Add IP to blacklist"""
        with self.lock:
            # Check if it's a CIDR range
            if '/' in ip:
                try:
                    network = ipaddress.ip_network(ip, strict=False)
                    if network not in self.blacklist_ranges:
                        self.blacklist_ranges.append(network)
                except ValueError:
                    return False
            else:
                self.blacklist.add(ip)
            
            # Remove from whitelist if present
            self.whitelist.discard(ip)
            
            self._save_data()
            return True
    
    def remove_from_whitelist(self, ip: str):
        """Remove IP from whitelist"""
        with self.lock:
            if '/' in ip:
                try:
                    network = ipaddress.ip_network(ip, strict=False)
                    self.whitelist_ranges = [r for r in self.whitelist_ranges if r != network]
                except ValueError:
                    return False
            else:
                self.whitelist.discard(ip)
            
            self._save_data()
            return True
    
    def remove_from_blacklist(self, ip: str):
        """Remove IP from blacklist"""
        with self.lock:
            if '/' in ip:
                try:
                    network = ipaddress.ip_network(ip, strict=False)
                    self.blacklist_ranges = [r for r in self.blacklist_ranges if r != network]
                except ValueError:
                    return False
            else:
                self.blacklist.discard(ip)
            
            self._save_data()
            return True
    
    def get_all_lists(self) -> dict:
        """Get all whitelist and blacklist entries"""
        with self.lock:
            return {
                'whitelist': list(self.whitelist),
                'blacklist': list(self.blacklist),
                'whitelist_ranges': [str(r) for r in self.whitelist_ranges],
                'blacklist_ranges': [str(r) for r in self.blacklist_ranges]
            }
    
    def clear_whitelist(self):
        """Clear all whitelist entries"""
        with self.lock:
            self.whitelist.clear()
            self.whitelist_ranges.clear()
            self._save_data()
    
    def clear_blacklist(self):
        """Clear all blacklist entries"""
        with self.lock:
            self.blacklist.clear()
            self.blacklist_ranges.clear()
            self._save_data()
