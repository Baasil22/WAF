"""
Bot Detection
Detects automated requests, scrapers, and malicious bots
"""
import re
from typing import Dict, Any, Optional, Tuple
from collections import defaultdict
import time


class BotDetector:
    """Detects automated bots and scrapers"""
    
    def __init__(self, security_level: str = 'medium'):
        self.security_level = security_level
        self._compile_patterns()
        
        # Request tracking for behavioral analysis
        self.request_timing = defaultdict(list)
        self.max_tracking_entries = 100
    
    def _compile_patterns(self):
        """Compile bot detection patterns"""
        
        # Known malicious bot user agents
        self.malicious_bots = [
            r'sqlmap',                           # SQL injection tool
            r'nikto',                            # Vulnerability scanner
            r'nmap',                             # Network scanner
            r'masscan',                          # Port scanner
            r'dirbuster',                        # Directory brute forcer
            r'gobuster',                         # Directory/DNS brute forcer
            r'wfuzz',                            # Web fuzzer
            r'ffuf',                             # Fast web fuzzer
            r'hydra',                            # Password cracker
            r'burp',                             # Burp Suite
            r'owasp',                            # OWASP ZAP
            r'acunetix',                         # Vulnerability scanner
            r'nessus',                           # Vulnerability scanner
            r'nuclei',                           # Vulnerability scanner
            r'w3af',                             # Web attack framework
            r'skipfish',                         # Web scanner
            r'arachni',                          # Web scanner
            r'jbrofuzz',                         # Fuzzer
            r'webinspect',                       # HP scanner
            r'paros',                            # Paros proxy
        ]
        
        # Suspicious bot patterns
        self.suspicious_bots = [
            r'python-requests',                  # Python requests (sometimes legitimate)
            r'python-urllib',                    # Python urllib
            r'curl/',                            # cURL
            r'wget/',                            # wget
            r'httpx/',                           # httpx
            r'axios/',                           # axios
            r'node-fetch',                       # Node.js fetch
            r'java/',                            # Java HTTP client
            r'libwww-perl',                      # Perl LWP
            r'lwp-trivial',                      # Perl LWP
            r'mechanize',                        # Mechanize library
            r'scrapy',                           # Scrapy spider
            r'phantom',                          # PhantomJS
            r'headless',                         # Headless browser indicators
            r'selenium',                         # Selenium
            r'puppeteer',                        # Puppeteer
            r'playwright',                       # Playwright
        ]
        
        # Known good bots (to whitelist)
        self.good_bots = [
            r'googlebot',
            r'bingbot',
            r'yandexbot',
            r'duckduckbot',
            r'baiduspider',
            r'facebookexternalhit',
            r'twitterbot',
            r'linkedinbot',
            r'slackbot',
            r'discordbot',
        ]
        
        # Empty or missing user agent indicators
        self.empty_ua_check = True
        
        self.compiled_malicious = [re.compile(p, re.IGNORECASE) for p in self.malicious_bots]
        self.compiled_suspicious = [re.compile(p, re.IGNORECASE) for p in self.suspicious_bots]
        self.compiled_good = [re.compile(p, re.IGNORECASE) for p in self.good_bots]
    
    def detect(self, request_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Detect bot activity
        
        Returns:
            Tuple of (is_attack, details)
        """
        user_agent = request_data.get('headers', {}).get('User-Agent', '')
        ip = request_data.get('ip', '')
        
        # Check for whitelisted good bots
        for pattern in self.compiled_good:
            if pattern.search(user_agent):
                return False, None
        
        # Check for missing/empty user agent
        if not user_agent or user_agent.strip() == '':
            if self.security_level in ['high', 'paranoid']:
                return True, {
                    'attack_type': 'Bot Detection',
                    'severity': 'medium',
                    'pattern': 'Empty User-Agent',
                    'field': 'user_agent',
                    'matched': 'No User-Agent header'
                }
        
        # Check for known malicious bots
        for pattern in self.compiled_malicious:
            if pattern.search(user_agent):
                return True, {
                    'attack_type': 'Bot Detection',
                    'severity': 'critical',
                    'pattern': pattern.pattern,
                    'field': 'user_agent',
                    'matched': user_agent[:100]
                }
        
        # Check for suspicious automated tools (high/paranoid only)
        if self.security_level in ['high', 'paranoid']:
            for pattern in self.compiled_suspicious:
                if pattern.search(user_agent):
                    return True, {
                        'attack_type': 'Bot Detection',
                        'severity': 'medium',
                        'pattern': pattern.pattern,
                        'field': 'user_agent',
                        'matched': user_agent[:100]
                    }
        
        # Check for behavioral patterns
        if self.security_level in ['high', 'paranoid']:
            behavioral_result = self._check_behavioral(ip, request_data)
            if behavioral_result:
                return True, behavioral_result
        
        return False, None
    
    def _check_behavioral(self, ip: str, request_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check behavioral patterns that indicate bot activity"""
        current_time = time.time()
        
        # Track request timing
        self.request_timing[ip].append(current_time)
        
        # Keep only recent requests (last 60 seconds)
        self.request_timing[ip] = [
            t for t in self.request_timing[ip] 
            if current_time - t < 60
        ][-self.max_tracking_entries:]
        
        recent_requests = len(self.request_timing[ip])
        
        # Check for suspiciously regular request intervals (bot-like behavior)
        if recent_requests >= 5:
            intervals = [
                self.request_timing[ip][i+1] - self.request_timing[ip][i]
                for i in range(len(self.request_timing[ip]) - 1)
            ]
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                
                # Check if intervals are too regular (within 10% of each other)
                if all(abs(i - avg_interval) < avg_interval * 0.1 for i in intervals):
                    if avg_interval < 1.0:  # Less than 1 second between requests
                        return {
                            'attack_type': 'Bot Detection',
                            'severity': 'high',
                            'pattern': 'Automated request pattern',
                            'field': 'behavioral',
                            'matched': f'{recent_requests} requests with regular {avg_interval:.2f}s intervals'
                        }
        
        return None
