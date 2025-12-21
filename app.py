"""
Web Application Firewall (WAF) - Main Application
A comprehensive WAF with real-time monitoring dashboard
"""
import os
import json
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response
from flask_socketio import SocketIO, emit

from config import Config
from waf import WAFMiddleware

# Create Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize SocketIO for real-time updates (using threading for Windows compatibility)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Ensure data directory exists
os.makedirs(Config.DATA_DIR, exist_ok=True)

# Initialize WAF middleware
waf = WAFMiddleware(app, Config)

# ============================================
# Authentication Decorator
# ============================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ============================================
# Authentication Routes
# ============================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == Config.ADMIN_USERNAME and password == Config.ADMIN_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """Logout"""
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# ============================================
# Dashboard Routes
# ============================================

@app.route('/')
def index():
    """Redirect to dashboard"""
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page"""
    stats = waf.get_stats()
    return render_template('dashboard.html', stats=stats)

@app.route('/dashboard/logs')
@login_required
def logs_page():
    """Attack logs page"""
    logs = waf.get_logs(limit=100)
    return render_template('logs.html', logs=logs)

@app.route('/dashboard/rules')
@login_required
def rules_page():
    """Rule management page"""
    ip_lists = waf.ip_filter.get_all_lists()
    rate_stats = {
        'max_requests': waf.rate_limiter.max_requests,
        'window_seconds': waf.rate_limiter.window_seconds,
        'ban_duration': waf.rate_limiter.ban_duration,
        'banned_ips': waf.rate_limiter.get_all_banned()
    }
    return render_template('rules.html', ip_lists=ip_lists, rate_stats=rate_stats)

@app.route('/dashboard/settings')
@login_required
def settings_page():
    """Settings page"""
    config_data = {
        'security_level': Config.SECURITY_LEVEL,
        'rate_limit_enabled': Config.RATE_LIMIT_ENABLED,
        'rate_limit_requests': Config.RATE_LIMIT_REQUESTS,
        'rate_limit_window': Config.RATE_LIMIT_WINDOW,
        'rate_limit_ban_duration': Config.RATE_LIMIT_BAN_DURATION,
        'waf_enabled': Config.WAF_ENABLED,
        'log_blocked_requests': Config.LOG_BLOCKED_REQUESTS,
        'log_all_requests': Config.LOG_ALL_REQUESTS
    }
    return render_template('settings.html', config=config_data)

# ============================================
# API Endpoints
# ============================================

@app.route('/api/stats')
@login_required
def api_stats():
    """Get WAF statistics"""
    return jsonify(waf.get_stats())

@app.route('/api/logs')
@login_required
def api_logs():
    """Get attack logs"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify(waf.get_logs(limit=limit))

@app.route('/api/logs/clear', methods=['POST'])
@login_required
def api_clear_logs():
    """Clear attack logs"""
    waf.clear_logs()
    return jsonify({'status': 'success', 'message': 'Logs cleared'})

@app.route('/api/logs/export')
@login_required
def api_export_logs():
    """Export attack logs as downloadable CSV file"""
    import csv
    import io
    from datetime import datetime
    from flask import send_file
    
    logs = waf.get_logs(limit=10000)
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header row
    writer.writerow(['Timestamp', 'IP Address', 'Attack Type', 'Severity', 'Path', 'Pattern Matched', 'Field', 'Method', 'User Agent'])
    
    # Write data rows
    for log in logs:
        writer.writerow([
            log.get('timestamp', ''),
            log.get('ip', ''),
            log.get('attack_type', ''),
            log.get('severity', ''),
            log.get('path', ''),
            log.get('matched', ''),
            log.get('field', ''),
            log.get('method', ''),
            log.get('user_agent', '')
        ])
    
    # Convert to bytes for send_file
    output.seek(0)
    byte_output = io.BytesIO(output.getvalue().encode('utf-8'))
    
    # Generate filename with timestamp
    filename = f'waf_attack_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    
    return send_file(
        byte_output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )



@app.route('/api/ip/blacklist', methods=['POST'])
@login_required
def api_blacklist_ip():
    """Add IP to blacklist"""
    data = request.get_json()
    ip = data.get('ip')
    if ip:
        waf.ip_filter.add_to_blacklist(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} blacklisted'})
    return jsonify({'status': 'error', 'message': 'No IP provided'}), 400

@app.route('/api/ip/whitelist', methods=['POST'])
@login_required
def api_whitelist_ip():
    """Add IP to whitelist"""
    data = request.get_json()
    ip = data.get('ip')
    if ip:
        waf.ip_filter.add_to_whitelist(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} whitelisted'})
    return jsonify({'status': 'error', 'message': 'No IP provided'}), 400

@app.route('/api/ip/blacklist/remove', methods=['POST'])
@login_required
def api_remove_blacklist():
    """Remove IP from blacklist"""
    data = request.get_json()
    ip = data.get('ip')
    if ip:
        waf.ip_filter.remove_from_blacklist(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} removed from blacklist'})
    return jsonify({'status': 'error', 'message': 'No IP provided'}), 400

@app.route('/api/ip/whitelist/remove', methods=['POST'])
@login_required
def api_remove_whitelist():
    """Remove IP from whitelist"""
    data = request.get_json()
    ip = data.get('ip')
    if ip:
        waf.ip_filter.remove_from_whitelist(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} removed from whitelist'})
    return jsonify({'status': 'error', 'message': 'No IP provided'}), 400

@app.route('/api/ip/lists')
@login_required
def api_ip_lists():
    """Get IP whitelist and blacklist"""
    return jsonify(waf.ip_filter.get_all_lists())

@app.route('/api/ratelimit/banned')
@login_required
def api_banned_ips():
    """Get rate-limited banned IPs"""
    return jsonify(waf.rate_limiter.get_all_banned())

@app.route('/api/ratelimit/unban', methods=['POST'])
@login_required
def api_unban_ip():
    """Unban a rate-limited IP"""
    data = request.get_json()
    ip = data.get('ip')
    if ip:
        waf.rate_limiter.unban_ip(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} unbanned'})
    return jsonify({'status': 'error', 'message': 'No IP provided'}), 400

@app.route('/api/stats/reset', methods=['POST'])
@login_required
def api_reset_stats():
    """Reset WAF statistics"""
    waf.reset_stats()
    return jsonify({'status': 'success', 'message': 'Statistics reset'})

@app.route('/api/config', methods=['GET'])
@login_required
def api_get_config():
    """Get current WAF configuration"""
    return jsonify({
        'security_level': Config.SECURITY_LEVEL,
        'rate_limit_enabled': Config.RATE_LIMIT_ENABLED,
        'rate_limit_requests': Config.RATE_LIMIT_REQUESTS,
        'rate_limit_window': Config.RATE_LIMIT_WINDOW,
        'rate_limit_ban_duration': Config.RATE_LIMIT_BAN_DURATION,
        'waf_enabled': Config.WAF_ENABLED,
        'log_blocked_requests': Config.LOG_BLOCKED_REQUESTS
    })

@app.route('/api/config/security-level', methods=['POST'])
@login_required
def api_set_security_level():
    """Update security level"""
    data = request.get_json()
    level = data.get('level')
    valid_levels = ['low', 'medium', 'high', 'paranoid']
    
    if level not in valid_levels:
        return jsonify({'status': 'error', 'message': 'Invalid security level'}), 400
    
    # Update config
    Config.SECURITY_LEVEL = level
    
    # Reinitialize detectors with new level
    waf.sql_detector = waf.sql_detector.__class__(level)
    waf.xss_detector = waf.xss_detector.__class__(level)
    waf.path_detector = waf.path_detector.__class__(level)
    waf.cmd_detector = waf.cmd_detector.__class__(level)
    
    return jsonify({'status': 'success', 'message': f'Security level set to {level}'})

@app.route('/api/config/ratelimit', methods=['POST'])
@login_required
def api_set_ratelimit():
    """Update rate limit settings"""
    data = request.get_json()
    
    max_requests = data.get('max_requests')
    window_seconds = data.get('window_seconds')
    ban_duration = data.get('ban_duration')
    
    # Update rate limiter settings
    if max_requests is not None:
        waf.rate_limiter.max_requests = int(max_requests)
        Config.RATE_LIMIT_REQUESTS = int(max_requests)
    
    if window_seconds is not None:
        waf.rate_limiter.window_seconds = int(window_seconds)
        Config.RATE_LIMIT_WINDOW = int(window_seconds)
    
    if ban_duration is not None:
        waf.rate_limiter.ban_duration = int(ban_duration)
        Config.RATE_LIMIT_BAN_DURATION = int(ban_duration)
    
    return jsonify({
        'status': 'success', 
        'message': 'Rate limit settings updated',
        'settings': {
            'max_requests': waf.rate_limiter.max_requests,
            'window_seconds': waf.rate_limiter.window_seconds,
            'ban_duration': waf.rate_limiter.ban_duration
        }
    })

# ============================================
# Test Endpoints (for testing WAF)
# ============================================

@app.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Test endpoint for WAF testing"""
    if request.method == 'POST':
        data = request.form.get('input', '') or request.get_json() or {}
        return jsonify({
            'status': 'success',
            'message': 'Request processed successfully',
            'data': str(data)
        })
    
    query = request.args.get('q', '')
    return jsonify({
        'status': 'success',
        'message': 'GET request processed',
        'query': query
    })

@app.route('/api/echo', methods=['POST'])
def echo_endpoint():
    """Echo endpoint for testing"""
    return jsonify({
        'status': 'success',
        'received': dict(request.form) or request.get_json() or {}
    })

# ============================================
# WebSocket Events
# ============================================

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    if session.get('logged_in'):
        emit('connected', {'status': 'connected'})

@socketio.on('get_stats')
def handle_get_stats():
    """Send current stats via WebSocket"""
    if session.get('logged_in'):
        emit('stats_update', waf.get_stats())

@socketio.on('get_logs')
def handle_get_logs():
    """Send logs via WebSocket"""
    if session.get('logged_in'):
        emit('logs_update', waf.get_logs(limit=50))

# ============================================
# Background task to broadcast stats
# ============================================

def background_stats_broadcast():
    """Broadcast stats to all connected clients periodically"""
    import time
    while True:
        socketio.sleep(2)
        socketio.emit('stats_update', waf.get_stats())
        socketio.emit('logs_update', waf.get_logs(limit=10))

# ============================================
# Run Application
# ============================================

if __name__ == '__main__':
    # Start background task
    socketio.start_background_task(background_stats_broadcast)
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║      🛡️  Web Application Firewall (WAF) Started  🛡️           ║
    ║                                                               ║
    ║  Dashboard: http://localhost:5050/dashboard                   ║
    ║  Login:     admin / admin123                                  ║
    ║                                                               ║
    ║  Protected endpoints: /api/test, /api/echo                    ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5050)
