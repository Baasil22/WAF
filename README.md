# WAFGuard - Advanced Web Application Firewall

A comprehensive, enterprise-grade Web Application Firewall built with Python Flask featuring **16+ attack detection modules** and a beautiful real-time dashboard.

## 🛡️ Attack Protection

### Core Detection (4 Modules)
| Attack Type | Description |
|-------------|-------------|
| **SQL Injection (SQLi)** | Detects UNION, boolean-based, error-based, and time-based SQL injection |
| **Cross-Site Scripting (XSS)** | Blocks script tags, event handlers, and encoded XSS payloads |
| **Path Traversal** | Prevents directory traversal attacks (../, encoded variants) |
| **Command Injection** | Detects shell commands, pipes, and command chaining |

### Advanced Detection (12 Modules)
| Attack Type | Description |
|-------------|-------------|
| **CSRF** | Cross-Site Request Forgery detection via Origin/Referer validation |
| **CRLF Injection** | HTTP header injection and response splitting attacks |
| **SSRF** | Server-Side Request Forgery with cloud metadata protection |
| **SSTI** | Server-Side Template Injection (Jinja2, Twig, ERB, etc.) |
| **XXE** | XML External Entity injection and DTD attacks |
| **LFI/RFI** | Local/Remote File Inclusion with wrapper detection |
| **Bot Detection** | Malicious bot identification and behavioral analysis |
| **Brute Force** | Login attempt rate limiting and credential stuffing detection |
| **Password Spraying** | Multi-IP password spraying attack detection |
| **Open Redirect** | URL redirection vulnerability protection |
| **Protocol Violation** | HTTP smuggling and protocol anomaly detection |
| **Payload Obfuscation** | Encoding bypass and evasion technique detection |
| **Insecure Deserialization** | Java, PHP, Python, .NET deserialization attacks |

### Additional Protection
- **Rate Limiting**: Configurable request limits with automatic IP banning
- **IP Management**: Blacklist/Whitelist with CIDR range support
- **Account Enumeration**: Sequential username pattern detection
- **Real-time Logging**: Detailed attack logs with CSV export

## 📸 Features

- 🎨 **Modern Dashboard**: Beautiful dark-themed UI with glassmorphism
- 📊 **Real-time Statistics**: Live attack monitoring and charts
- 📱 **Responsive Design**: Works on mobile, tablet, and desktop
- 🔧 **Web Configuration**: All settings editable from UI
- 📥 **Log Export**: Download attack logs as CSV
- 🔒 **4 Security Levels**: Low, Medium, High, Paranoid

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
Open your browser: `http://localhost:5050`

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
│   ├── middleware.py      # Request interceptor (16+ detectors)
│   ├── rate_limiter.py    # Rate limiting logic
│   ├── ip_filter.py       # IP blacklist/whitelist
│   └── rules/             # Detection modules
│       ├── sql_injection.py
│       ├── xss.py
│       ├── path_traversal.py
│       ├── command_injection.py
│       ├── csrf.py
│       ├── crlf.py
│       ├── ssrf.py
│       ├── ssti.py
│       ├── xxe.py
│       ├── file_inclusion.py
│       ├── bot_detection.py
│       ├── auth_attack.py
│       ├── open_redirect.py
│       ├── protocol_violation.py
│       ├── obfuscation.py
│       └── deserialization.py
├── templates/             # HTML templates
└── static/                # CSS & JavaScript
```

## ⚙️ Configuration

Edit `config.py` or use the web interface:

```python
# Security level: low, medium, high, paranoid
SECURITY_LEVEL = 'high'

# Rate limiting
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_BAN_DURATION = 300
```

## 🔒 Security Levels

| Level | Sensitivity | Use Case |
|-------|-------------|----------|
| Low | Basic patterns only | High-traffic production |
| Medium | Balanced detection | Recommended default |
| High | Strict detection | Sensitive applications |
| Paranoid | Maximum security | Security-critical systems |

## 🧪 Testing Attacks

```bash
# SQL Injection
curl "http://localhost:5050/api/test?id=' OR '1'='1"

# XSS
curl "http://localhost:5050/api/test?q=<script>alert(1)</script>"

# SSRF (Cloud Metadata)
curl "http://localhost:5050/api/test?url=http://169.254.169.254/latest/meta-data/"

# SSTI
curl "http://localhost:5050/api/test?name={{7*7}}"

# XXE
curl -X POST "http://localhost:5050/api/test" -H "Content-Type: application/xml" -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'

# Command Injection
curl "http://localhost:5050/api/test?cmd=; cat /etc/passwd"

# LFI
curl "http://localhost:5050/api/test?file=../../../etc/passwd"

# Path Traversal
curl "http://localhost:5050/api/test?path=....//....//etc/passwd"
```

## 🛠️ API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | WAF statistics |
| `/api/logs` | GET | Attack logs |
| `/api/logs/clear` | POST | Clear logs |
| `/api/logs/export` | GET | Export CSV |
| `/api/ip/blacklist` | POST/DELETE | Manage blacklist |
| `/api/ip/whitelist` | POST/DELETE | Manage whitelist |
| `/api/config/security-level` | POST | Update security level |
| `/api/config/ratelimit` | POST | Update rate limits |

## 📄 License

MIT License

## 👤 Author

**Baasil**

- GitHub: [@Baasil22](https://github.com/Baasil22)

---

⭐ Star this repo if you find it useful!
