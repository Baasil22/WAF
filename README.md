# WAFGuard - Web Application Firewall

A modern, feature-rich Web Application Firewall built with Python Flask featuring a beautiful real-time dashboard.

## 🛡️ Features

- **Attack Detection**: SQL Injection, XSS, Path Traversal, Command Injection
- **Rate Limiting**: Configurable request limits with automatic IP banning
- **IP Management**: Blacklist/Whitelist with CIDR range support
- **Real-time Dashboard**: Beautiful dark-themed UI with live stats
- **Responsive Design**: Works on all devices (mobile, tablet, desktop)
- **Attack Logs**: Detailed logging with CSV export
- **Configurable Security Levels**: Low, Medium, High, Paranoid

## 📸 Screenshots

### Dashboard
Real-time monitoring with attack statistics and distribution charts.

### Attack Logs
Detailed attack logs with filtering, search, and export functionality.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/Baasil22/WAF.git
cd WAF

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Access Dashboard
Open your browser and go to: `http://localhost:5050`

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

## 📁 Project Structure

```
WAF/
├── app.py                 # Main Flask application
├── config.py              # Configuration settings
├── requirements.txt       # Python dependencies
├── waf/                   # WAF core module
│   ├── middleware.py      # Request interceptor
│   ├── rate_limiter.py    # Rate limiting logic
│   ├── ip_filter.py       # IP blacklist/whitelist
│   └── rules/             # Detection rules
│       ├── sql_injection.py
│       ├── xss.py
│       ├── path_traversal.py
│       └── command_injection.py
├── templates/             # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── logs.html
│   ├── rules.html
│   └── settings.html
├── static/                # Static assets
│   ├── css/style.css
│   └── js/dashboard.js
└── data/                  # Data storage
    ├── attack_logs.json
    └── blocked_ips.json
```

## ⚙️ Configuration

Edit `config.py` to customize:

```python
# Security level: low, medium, high, paranoid
SECURITY_LEVEL = 'high'

# Rate limiting
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_BAN_DURATION = 300

# Dashboard credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'
```

## 🔒 Security Levels

| Level | Description |
|-------|-------------|
| Low | Basic protection, minimal false positives |
| Medium | Balanced protection (recommended) |
| High | Strict protection |
| Paranoid | Maximum security, may block legitimate requests |

## 🛠️ API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Get WAF statistics |
| `/api/logs` | GET | Get attack logs |
| `/api/logs/clear` | POST | Clear all logs |
| `/api/logs/export` | GET | Export logs as CSV |
| `/api/ip/blacklist` | POST | Add IP to blacklist |
| `/api/ip/whitelist` | POST | Add IP to whitelist |
| `/api/config/security-level` | POST | Update security level |
| `/api/config/ratelimit` | POST | Update rate limit settings |

## 📱 Responsive Design

The dashboard is fully responsive and works on:
- 📱 Mobile phones (360px+)
- 📱 Tablets / iPad (768px+)
- 💻 Laptops (992px+)
- 🖥️ Desktop monitors (1200px+)

## 🧪 Testing Attacks

Simulate attacks to test the WAF:

```bash
# SQL Injection
curl "http://localhost:5050/api/test?id=' OR '1'='1"

# XSS
curl "http://localhost:5050/api/test?q=<script>alert(1)</script>"

# Path Traversal
curl "http://localhost:5050/api/test?file=../../../etc/passwd"

# Command Injection
curl "http://localhost:5050/api/test?cmd=; cat /etc/passwd"
```

## 📄 License

MIT License

## 👤 Author

**Baasil**

- GitHub: [@Baasil22](https://github.com/Baasil22)
