"""
WAF Configuration Settings
"""
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask Settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'waf-secret-key-change-in-production')
    DEBUG = os.environ.get('DEBUG', True)
    
    # WAF Settings
    WAF_ENABLED = True
    LOG_BLOCKED_REQUESTS = True
    LOG_ALL_REQUESTS = True
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_REQUESTS = 100  # Max requests
    RATE_LIMIT_WINDOW = 60     # Per seconds
    RATE_LIMIT_BAN_DURATION = 300  # Ban duration in seconds
    
    # Security Levels: 'low', 'medium', 'high', 'paranoid'
    SECURITY_LEVEL = 'paranoid'  # EXTREME protection mode
    
    # Dashboard Auth
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
    
    # Data Storage
    DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
    RULES_FILE = os.path.join(DATA_DIR, 'rules.json')
    BLOCKED_IPS_FILE = os.path.join(DATA_DIR, 'blocked_ips.json')
    LOGS_FILE = os.path.join(DATA_DIR, 'attack_logs.json')
