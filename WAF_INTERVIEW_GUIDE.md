# 🛡️ Web Application Firewall (WAF) - Complete Interview Guide

## Project Overview

This is a **Python-based Web Application Firewall (WAF)** built from scratch using Flask. It provides real-time protection against web-based attacks and includes a modern admin dashboard for monitoring and configuration.

---

## 🎯 What is a WAF?

A **Web Application Firewall (WAF)** is a security system that monitors, filters, and blocks malicious HTTP traffic between a web application and the Internet. Unlike traditional firewalls that protect at the network level, WAFs operate at the application layer (Layer 7 of the OSI model).

**Key Purpose**: Protect web applications from attacks like SQL Injection, Cross-Site Scripting (XSS), and other OWASP Top 10 vulnerabilities.

---

## 📁 Project Architecture

```
WAF/
├── app.py                 # Main Flask application
├── config.py              # Configuration settings
├── requirements.txt       # Python dependencies
├── waf/                   # Core WAF engine
│   ├── __init__.py        # WAF initialization
│   ├── middleware.py      # Request interception middleware
│   ├── ip_filter.py       # IP blacklist/whitelist management
│   ├── rate_limiter.py    # Rate limiting engine
│   └── rules/             # Attack detection modules
│       ├── sql_injection.py
│       ├── xss.py
│       ├── csrf.py
│       ├── ssrf.py
│       ├── xxe.py
│       ├── ssti.py
│       ├── command_injection.py
│       ├── path_traversal.py
│       ├── file_inclusion.py
│       ├── auth_attack.py
│       ├── bot_detection.py
│       ├── crlf.py
│       ├── deserialization.py
│       ├── obfuscation.py
│       ├── open_redirect.py
│       └── protocol_violation.py
├── templates/             # HTML templates (Jinja2)
├── static/               # CSS, JavaScript
└── data/                 # JSON data storage
```

---

## 🛡️ Attack Types Detected (17 Categories)

### 1. **SQL Injection**
- **What it is**: Attacker injects malicious SQL code into queries
- **Example**: `' OR '1'='1' --`
- **How WAF blocks**: Pattern matching for SQL keywords like `SELECT`, `UNION`, `DROP`, comments (`--`, `/*`)
- **Impact**: Database theft, data modification, authentication bypass

### 2. **Cross-Site Scripting (XSS)**
- **What it is**: Attacker injects malicious JavaScript into pages
- **Example**: `<script>alert('hacked')</script>`
- **How WAF blocks**: Detects `<script>`, `onerror=`, `javascript:`, event handlers
- **Impact**: Session hijacking, cookie theft, phishing

### 3. **Command Injection**
- **What it is**: Attacker executes system commands on the server
- **Example**: `; rm -rf /` or `| cat /etc/passwd`
- **How WAF blocks**: Detects shell operators like `;`, `|`, `&&`, `$()`
- **Impact**: Full server compromise

### 4. **Path Traversal (Directory Traversal)**
- **What it is**: Attacker accesses files outside web root
- **Example**: `../../etc/passwd`
- **How WAF blocks**: Detects `../`, `..\\`, encoded variants
- **Impact**: Sensitive file exposure

### 5. **Local File Inclusion (LFI) / Remote File Inclusion (RFI)**
- **What it is**: Include malicious files into the application
- **Example**: `?file=http://evil.com/shell.php`
- **How WAF blocks**: Detects file paths, PHP wrappers (`php://filter`)
- **Impact**: Code execution, information disclosure

### 6. **Server-Side Request Forgery (SSRF)**
- **What it is**: Attacker tricks server into making internal requests
- **Example**: `?url=http://127.0.0.1:22`
- **How WAF blocks**: Detects internal IPs, localhost, cloud metadata URLs
- **Impact**: Internal service access, cloud credential theft

### 7. **XML External Entity (XXE)**
- **What it is**: Attacker exploits XML parsers to access server files
- **Example**: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
- **How WAF blocks**: Detects DOCTYPE, ENTITY declarations
- **Impact**: File disclosure, SSRF, DoS

### 8. **Server-Side Template Injection (SSTI)**
- **What it is**: Inject code into server-side templates
- **Example**: `{{7*7}}` or `${system('id')}`
- **How WAF blocks**: Detects Jinja2, Freemarker, Velocity syntax
- **Impact**: Remote code execution

### 9. **Cross-Site Request Forgery (CSRF)**
- **What it is**: Trick authenticated users into performing unwanted actions
- **How WAF blocks**: Validates Origin/Referer headers, token verification
- **Impact**: Unauthorized actions on behalf of users

### 10. **CRLF Injection**
- **What it is**: Inject carriage return/line feed characters
- **Example**: `%0d%0aSet-Cookie:hacked=true`
- **How WAF blocks**: Detects `\r\n`, `%0d%0a` in headers
- **Impact**: HTTP response splitting, cache poisoning

### 11. **Authentication Attacks**
- **Brute Force**: Multiple login attempts
- **Credential Stuffing**: Using leaked credentials
- **Password Spraying**: Common passwords across users
- **How WAF blocks**: Rate limiting, pattern detection, account lockout

### 12. **Bot Detection**
- **What it is**: Identify automated tools and scripts
- **How WAF blocks**: User-Agent analysis, behavior patterns, known bot signatures
- **Impact**: Prevents scraping, DDoS, automated attacks

### 13. **Open Redirect**
- **What it is**: Redirect users to malicious sites
- **Example**: `?redirect=http://evil.com`
- **How WAF blocks**: Validates redirect URLs, detects external domains
- **Impact**: Phishing, credential theft

### 14. **Insecure Deserialization**
- **What it is**: Execute code via malicious serialized objects
- **How WAF blocks**: Detects Java/Python/PHP serialization signatures
- **Impact**: Remote code execution

### 15. **Protocol Violations**
- **What it is**: Malformed HTTP requests
- **How WAF blocks**: Validates HTTP methods, headers, request structure
- **Impact**: Application errors, bypasses

### 16. **Payload Obfuscation Detection**
- **What it is**: Encoding attacks to evade detection
- **Examples**: URL encoding, Unicode, Base64, case mixing
- **How WAF blocks**: Recursive decoding, normalization
- **Impact**: Prevents evasion techniques

---

## 🔧 Core Components Explained

### 1. **WAF Middleware** (`waf/middleware.py`)
- Intercepts ALL incoming HTTP requests using Flask's `before_request` hook
- Inspects: URL parameters, form data, JSON body, headers, cookies
- If attack detected → Block request with 403/400 error
- If clean → Allow request to continue to the application

### 2. **Rate Limiter** (`waf/rate_limiter.py`)
- Uses **Token Bucket Algorithm**
- Tracks requests per IP within a time window
- If exceeded → Temporarily ban the IP
- Prevents: Brute force, DDoS, enumeration attacks
- Configuration: Max requests (100), Window (60 seconds), Ban duration (300 seconds)

### 3. **IP Filter** (`waf/ip_filter.py`)
- **Whitelist**: Always allowed, bypasses all checks
- **Blacklist**: Always blocked immediately
- Stored in JSON files for persistence

### 4. **Attack Detectors** (`waf/rules/*.py`)
- Each file contains regex patterns for specific attack types
- Supports 4 security levels: Low, Medium, High, Paranoid
- Higher levels = more patterns = more false positives but better security

---

## 🖥️ Dashboard Features

### Real-Time Statistics Dashboard
- **Total Requests**: All HTTP requests processed
- **Blocked Requests**: Attacks detected and blocked
- **Block Rate**: Percentage of malicious traffic
- **Uptime**: Time since WAF started

### Attack Breakdown
- SQL Injection blocked count
- XSS attacks blocked count
- Path Traversal blocked count
- Command Injection blocked count
- Rate limited requests count
- IP blacklist blocks count

### Attack Logs Page
- Real-time attack feed
- Details: Timestamp, IP, Attack type, Path, Pattern matched
- Export logs as CSV
- Clear logs functionality

### IP Management
- Add/remove IPs from whitelist
- Add/remove IPs from blacklist
- View/unban rate-limited IPs

### Settings
- Change security level (Low/Medium/High/Paranoid)
- Configure rate limiting parameters
- Toggle WAF on/off

---

## 🔐 Security Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| **Low** | Basic patterns only | Development, testing |
| **Medium** | Standard protection | General websites |
| **High** | Comprehensive rules | E-commerce, banking |
| **Paranoid** | Maximum security | Critical systems |

---

## 💻 Technologies Used

| Technology | Purpose |
|------------|---------|
| **Python 3** | Primary language |
| **Flask** | Web framework |
| **Flask-SocketIO** | Real-time WebSocket updates |
| **Jinja2** | HTML templating |
| **Regular Expressions** | Pattern matching for attack detection |
| **JSON** | Data storage (logs, IP lists, stats) |
| **HTML/CSS/JavaScript** | Frontend dashboard |

---

## 🚀 How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py

# Access dashboard
http://localhost:5050/dashboard

# Login credentials
Username: admin
Password: admin123
```

---

## 📋 Common HR Interview Questions & Answers

### Q1: What is a WAF and how does it differ from a traditional firewall?

**Answer**: A WAF (Web Application Firewall) operates at the application layer (Layer 7) and analyzer HTTP/HTTPS traffic. Traditional firewalls work at the network layer (Layer 3/4) and filter by IP addresses and ports. WAFs understand web protocols and can detect attacks embedded in HTTP requests like SQL injection and XSS.

---

### Q2: Explain the architecture of your WAF project.

**Answer**: The WAF uses a middleware architecture:
1. **Request Interception**: Flask's `before_request` hook captures all incoming requests
2. **Multi-Layer Detection**: Request passes through IP filter → Rate limiter → Attack detectors
3. **Pattern Matching**: 17 specialized detectors scan for attack signatures using regex
4. **Decision Engine**: If any detector flags an attack, request is blocked with appropriate HTTP error
5. **Logging**: All blocked requests are logged with full details
6. **Dashboard**: Admin UI shows real-time stats via WebSocket

---

### Q3: How does your SQL Injection detection work?

**Answer**: The SQL injection detector uses:
1. **Regex Patterns**: Match keywords like `UNION SELECT`, `OR 1=1`, comments `--`, `/**/`
2. **Encoding Detection**: Decodes URL-encoded and Unicode payloads
3. **Context Analysis**: Different patterns for different injection points (URL, form, cookie)
4. **Security Levels**: Higher levels add more patterns (e.g., blind SQLi detection)

Example blocked:
```
Input: ' OR '1'='1' --
Detection: Matches quote + OR + always-true condition + comment
```

---

### Q4: What is rate limiting and how did you implement it?

**Answer**: Rate limiting prevents abuse by tracking request frequency per IP:
1. **Token Bucket Algorithm**: Each IP gets tokens, consumed per request, refilled over time
2. **Sliding Window**: Track requests in last 60 seconds
3. **Thresholds**: Max 100 requests per window (configurable)
4. **Consequences**: Exceeding limit = temporary IP ban (5 minutes default)
5. **Persistence**: Banned IPs stored in memory with expiration

---

### Q5: How do you handle false positives?

**Answer**: Multiple strategies:
1. **Security Levels**: Lower levels = fewer patterns = fewer false positives
2. **Whitelist**: Exempt trusted IPs from all checks
3. **Context Awareness**: Check where the pattern matched (URL vs. body)
4. **Fine-tuned Patterns**: Avoid overly broad regex
5. **Logging**: All blocks are logged for review and rule adjustment

---

### Q6: How would you deploy this in production?

**Answer**: Production deployment considerations:
1. **Reverse Proxy**: Place WAF behind Nginx/HAProxy
2. **HTTPS**: Add SSL termination
3. **Database**: Replace JSON with PostgreSQL/Redis
4. **Scaling**: Use Gunicorn/uWSGI with multiple workers
5. **Monitoring**: Add metrics (Prometheus), alerts
6. **Updates**: Regularly update attack rules
7. **Failover**: Have fallback if WAF fails (fail-open vs fail-close)

---

### Q7: What are the OWASP Top 10?

**Answer**: OWASP Top 10 (2021):
1. **Broken Access Control** - My WAF has auth checks
2. **Cryptographic Failures** - Not WAF scope, app responsibility
3. **Injection** - Covered (SQL, Command, SSTI, LDAP)
4. **Insecure Design** - Not WAF scope
5. **Security Misconfiguration** - WAF has secure defaults
6. **Vulnerable Components** - Not WAF scope
7. **Authentication Failures** - Brute force protection
8. **Data Integrity Failures** - Deserialization detection
9. **Logging Failures** - Comprehensive logging included
10. **SSRF** - Covered with SSRF detector

---

### Q8: What challenges did you face?

**Answer**: Key challenges:
1. **False Positives**: Balancing security vs usability
2. **Evasion Techniques**: Attackers use encoding, obfuscation - solved with recursive decoding
3. **Performance**: Regex can be slow - optimized patterns, compiled regex
4. **Real-time Updates**: WebSocket integration for live dashboard
5. **Windows Compatibility**: Had to use threading mode for SocketIO

---

### Q9: How is this different from commercial WAFs like AWS WAF or Cloudflare?

**Answer**: 
| Feature | My WAF | Commercial WAFs |
|---------|--------|-----------------|
| Cost | Free | Paid per request |
| Rules | Customizable | Predefined + custom |
| Scale | Single server | Global CDN |
| Support | Self-maintained | 24/7 support |
| Updates | Manual | Automatic |
| Learning | Educational | Production-ready |

My WAF is great for learning, development, or small-scale use. Commercial WAFs offer enterprise features.

---

### Q10: What would you add next?

**Answer**: Future improvements:
1. **Machine Learning**: Anomaly detection, behavioral analysis
2. **API Protection**: Rate limiting per API key, schema validation
3. **Geo-blocking**: Block requests from specific countries
4. **Bot Scoring**: CAPTCHA challenge for suspicious traffic
5. **Database Backend**: PostgreSQL for logs, Redis for rate limiting
6. **Rule Editor**: GUI for creating custom rules
7. **Integration**: Slack/Email alerts for attacks

---

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Get WAF statistics |
| `/api/logs` | GET | Get attack logs |
| `/api/logs/clear` | POST | Clear all logs |
| `/api/logs/export` | GET | Export logs as CSV |
| `/api/ip/blacklist` | POST | Add IP to blacklist |
| `/api/ip/whitelist` | POST | Add IP to whitelist |
| `/api/stats/reset` | POST | Reset all statistics |
| `/api/config/security-level` | POST | Change security level |

---

## 🧪 Testing the WAF

### Test SQL Injection (should be blocked):
```
curl "http://localhost:5050/api/test?q=' OR 1=1 --"
```

### Test XSS (should be blocked):
```
curl "http://localhost:5050/api/test?q=<script>alert('xss')</script>"
```

### Test Command Injection (should be blocked):
```
curl "http://localhost:5050/api/test?q=; cat /etc/passwd"
```

### Test Normal Request (should pass):
```
curl "http://localhost:5050/api/test?q=hello world"
```

---

## ✅ Key Takeaways for Interview

1. **Security Focus**: WAF protects against OWASP Top 10 attacks
2. **Defense in Depth**: Multiple layers (IP filter + Rate limit + 17 detectors)
3. **Real-time Monitoring**: WebSocket-powered dashboard
4. **Configurable**: 4 security levels, customizable thresholds
5. **Production Concepts**: Rate limiting, IP management, logging
6. **Python Best Practices**: Decorators, middleware pattern, modular design

---

*Good luck with your interview! 🎯*
