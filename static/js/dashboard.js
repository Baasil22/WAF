/**
 * WAFGuard Dashboard JavaScript
 * Real-time updates and interactive functionality - FULLY FUNCTIONAL VERSION
 */

// ============================================
// Socket.IO Connection
// ============================================

let socket = null;

function initSocket() {
    try {
        socket = io();

        socket.on('connect', function () {
            console.log('Connected to WAF server');
        });

        socket.on('stats_update', function (data) {
            updateStatsDisplay(data);
        });

        socket.on('logs_update', function (data) {
            updateRecentAttacks(data);
        });

    } catch (e) {
        console.log('Socket.IO not available, using polling');
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function () {
    initSocket();

    // Auto-refresh stats every 5 seconds
    setInterval(function () {
        refreshStats();
        loadRecentAttacks();
    }, 5000);

    // Initial load
    refreshStats();
    loadRecentAttacks();
});

// ============================================
// Stats Display
// ============================================

function updateStatsDisplay(stats) {
    if (!stats) return;

    // Update main stats
    const totalReqs = document.getElementById('total-requests');
    const blockedReqs = document.getElementById('blocked-requests');
    const uptime = document.getElementById('uptime');
    const blockRate = document.getElementById('block-rate');

    if (totalReqs) animateNumber(totalReqs, stats.total_requests);
    if (blockedReqs) animateNumber(blockedReqs, stats.blocked_requests);
    if (uptime) uptime.textContent = stats.uptime_formatted;
    if (blockRate) blockRate.textContent = stats.block_rate + '%';

    // Update attack type counts
    const sqlBlocked = document.getElementById('sql-blocked');
    const xssBlocked = document.getElementById('xss-blocked');
    const pathBlocked = document.getElementById('path-blocked');
    const cmdBlocked = document.getElementById('cmd-blocked');
    const rateBlocked = document.getElementById('rate-blocked');
    const ipBlocked = document.getElementById('ip-blocked');

    if (sqlBlocked) animateNumber(sqlBlocked, stats.sql_injection_blocked);
    if (xssBlocked) animateNumber(xssBlocked, stats.xss_blocked);
    if (pathBlocked) animateNumber(pathBlocked, stats.path_traversal_blocked);
    if (cmdBlocked) animateNumber(cmdBlocked, stats.command_injection_blocked);
    if (rateBlocked) animateNumber(rateBlocked, stats.rate_limited);
    if (ipBlocked) animateNumber(ipBlocked, stats.ip_blocked);

    updateAttackBars(stats);
}

function animateNumber(element, targetValue) {
    const currentValue = parseInt(element.textContent) || 0;
    if (currentValue !== targetValue) {
        element.textContent = targetValue;
        element.style.transform = 'scale(1.1)';
        setTimeout(() => {
            element.style.transform = 'scale(1)';
        }, 150);
    }
}

function updateAttackBars(stats) {
    if (!stats) return;

    const total = stats.blocked_requests || 1;

    const bars = {
        'sql-bar': stats.sql_injection_blocked,
        'xss-bar': stats.xss_blocked,
        'path-bar': stats.path_traversal_blocked,
        'cmd-bar': stats.command_injection_blocked,
        'rate-bar': stats.rate_limited,
        'ip-bar': stats.ip_blocked
    };

    for (const [id, value] of Object.entries(bars)) {
        const bar = document.getElementById(id);
        if (bar) {
            const percentage = Math.min((value / total) * 100, 100);
            bar.style.width = percentage + '%';
        }
    }
}

// ============================================
// Recent Attacks Display
// ============================================

function updateRecentAttacks(logs) {
    const container = document.getElementById('recent-attacks');
    if (!container) return;

    if (!logs || logs.length === 0) {
        container.innerHTML = `
            <div class="loading-placeholder">
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="width: 40px; height: 40px; color: var(--success);">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <polyline points="9,12 11,14 15,10" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <span>No recent attacks - All clear!</span>
            </div>
        `;
        return;
    }

    let html = '';
    logs.slice(0, 10).forEach(log => {
        const iconClass = getAttackIconClass(log.attack_type);
        const timeAgo = getTimeAgo(log.timestamp);

        html += `
            <div class="attack-item">
                <div class="attack-item-icon ${iconClass}">
                    ${getAttackIcon(log.attack_type)}
                </div>
                <div class="attack-item-content">
                    <div class="attack-item-type">${log.attack_type}</div>
                    <div class="attack-item-ip">${log.ip}</div>
                </div>
                <div class="attack-item-time">${timeAgo}</div>
            </div>
        `;
    });

    container.innerHTML = html;
}

function getAttackIconClass(type) {
    const typeMap = {
        'SQL Injection': 'sql',
        'XSS': 'xss',
        'Path Traversal': 'path',
        'Command Injection': 'cmd',
        'Rate Limit': 'rate',
        'IP Blacklisted': 'ip'
    };
    return typeMap[type] || 'sql';
}

function getAttackIcon(type) {
    const icons = {
        'SQL Injection': '<svg viewBox="0 0 24 24" fill="none"><ellipse cx="12" cy="5" rx="9" ry="3" stroke="currentColor" stroke-width="2"/><path d="M3 5V19C3 20.66 7.03 22 12 22C16.97 22 21 20.66 21 19V5" stroke="currentColor" stroke-width="2"/></svg>',
        'XSS': '<svg viewBox="0 0 24 24" fill="none"><polyline points="16,18 22,12 16,6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="8,6 2,12 8,18" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        'Path Traversal': '<svg viewBox="0 0 24 24" fill="none"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        'Command Injection': '<svg viewBox="0 0 24 24" fill="none"><rect x="2" y="4" width="20" height="16" rx="2" stroke="currentColor" stroke-width="2"/><path d="M6 9L9 12L6 15" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        'Rate Limit': '<svg viewBox="0 0 24 24" fill="none"><path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        'IP Blacklisted': '<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07" stroke="currentColor" stroke-width="2"/></svg>'
    };
    return icons[type] || icons['SQL Injection'];
}

function getTimeAgo(timestamp) {
    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now - then;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);

    if (diffSec < 60) return 'Just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHour < 24) return `${diffHour}h ago`;
    return `${Math.floor(diffHour / 24)}d ago`;
}

// ============================================
// API Calls
// ============================================

function refreshStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            updateStatsDisplay(data);
        })
        .catch(err => console.error('Failed to fetch stats:', err));
}

function loadRecentAttacks() {
    fetch('/api/logs?limit=10')
        .then(response => response.json())
        .then(data => {
            updateRecentAttacks(data);
        })
        .catch(err => console.error('Failed to fetch logs:', err));
}

function clearLogs() {
    if (confirm('Are you sure you want to clear all attack logs?')) {
        fetch('/api/logs/clear', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                showNotification('Logs cleared successfully', 'success');
                loadRecentAttacks();
                setTimeout(() => location.reload(), 500);
            })
            .catch(err => showNotification('Failed to clear logs: ' + err, 'error'));
    }
}

function resetStats() {
    if (confirm('Are you sure you want to reset all statistics?')) {
        fetch('/api/stats/reset', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                showNotification('Statistics reset successfully', 'success');
                refreshStats();
            })
            .catch(err => showNotification('Failed to reset stats: ' + err, 'error'));
    }
}

// ============================================
// IP Management - FULLY WORKING
// ============================================

function addToBlacklist(ip) {
    if (!ip) {
        const input = document.getElementById('blacklist-ip-input');
        if (input) ip = input.value.trim();
    }
    if (!ip) {
        showNotification('Please enter an IP address', 'error');
        return;
    }

    console.log('Adding to blacklist:', ip);

    fetch('/api/ip/blacklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
        .then(response => response.json())
        .then(data => {
            console.log('Blacklist response:', data);
            showNotification(data.message || 'IP added to blacklist', 'success');
            const input = document.getElementById('blacklist-ip-input');
            if (input) input.value = '';
            setTimeout(() => location.reload(), 500);
        })
        .catch(err => {
            console.error('Blacklist error:', err);
            showNotification('Failed to add IP: ' + err, 'error');
        });
}

function removeFromBlacklist(ip) {
    console.log('Removing from blacklist:', ip);

    fetch('/api/ip/blacklist/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
        .then(response => response.json())
        .then(data => {
            console.log('Remove response:', data);
            showNotification(data.message || 'IP removed from blacklist', 'success');
            setTimeout(() => location.reload(), 500);
        })
        .catch(err => {
            console.error('Remove error:', err);
            showNotification('Failed to remove IP: ' + err, 'error');
        });
}

function addToWhitelist(ip) {
    if (!ip) {
        const input = document.getElementById('whitelist-ip-input');
        if (input) ip = input.value.trim();
    }
    if (!ip) {
        showNotification('Please enter an IP address', 'error');
        return;
    }

    console.log('Adding to whitelist:', ip);

    fetch('/api/ip/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
        .then(response => response.json())
        .then(data => {
            console.log('Whitelist response:', data);
            showNotification(data.message || 'IP added to whitelist', 'success');
            const input = document.getElementById('whitelist-ip-input');
            if (input) input.value = '';
            setTimeout(() => location.reload(), 500);
        })
        .catch(err => {
            console.error('Whitelist error:', err);
            showNotification('Failed to add IP: ' + err, 'error');
        });
}

function removeFromWhitelist(ip) {
    console.log('Removing from whitelist:', ip);

    fetch('/api/ip/whitelist/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
        .then(response => response.json())
        .then(data => {
            console.log('Remove response:', data);
            showNotification(data.message || 'IP removed from whitelist', 'success');
            setTimeout(() => location.reload(), 500);
        })
        .catch(err => {
            console.error('Remove error:', err);
            showNotification('Failed to remove IP: ' + err, 'error');
        });
}

function unbanIP(ip) {
    console.log('Unbanning IP:', ip);

    fetch('/api/ratelimit/unban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
        .then(response => response.json())
        .then(data => {
            showNotification(data.message || 'IP unbanned', 'success');
            setTimeout(() => location.reload(), 500);
        })
        .catch(err => showNotification('Failed to unban IP: ' + err, 'error'));
}

// ============================================
// Settings - FULLY WORKING
// ============================================

function setSecurityLevel(level) {
    console.log('Setting security level:', level);

    fetch('/api/config/security-level', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ level: level })
    })
        .then(response => response.json())
        .then(data => {
            console.log('Security level response:', data);
            showNotification(data.message || 'Security level updated', 'success');

            // Update UI
            document.querySelectorAll('.level-option').forEach(opt => {
                opt.classList.remove('active');
            });
            const radio = document.querySelector(`input[value="${level}"]`);
            if (radio) {
                radio.checked = true;
                radio.closest('.level-option').classList.add('active');
            }
            const levelDisplay = document.getElementById('current-level');
            if (levelDisplay) {
                levelDisplay.textContent = level.toUpperCase();
            }
        })
        .catch(err => showNotification('Failed to update security level: ' + err, 'error'));
}

function updateRateLimit() {
    const maxRequests = document.getElementById('rate-max-requests')?.value;
    const windowSeconds = document.getElementById('rate-window')?.value;
    const banDuration = document.getElementById('rate-ban-duration')?.value;

    console.log('Updating rate limit:', { maxRequests, windowSeconds, banDuration });

    fetch('/api/config/ratelimit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            max_requests: parseInt(maxRequests),
            window_seconds: parseInt(windowSeconds),
            ban_duration: parseInt(banDuration)
        })
    })
        .then(response => response.json())
        .then(data => {
            console.log('Rate limit response:', data);
            showNotification(data.message || 'Rate limit settings updated', 'success');
        })
        .catch(err => showNotification('Failed to update rate limit: ' + err, 'error'));
}

// ============================================
// Modal Functions
// ============================================

let currentModalAction = null;

function showBlockIPModal() {
    currentModalAction = 'block';
    const modal = document.getElementById('ipModal');
    const title = document.getElementById('modalTitle');
    const action = document.getElementById('modalAction');
    const input = document.getElementById('ipInput');

    if (title) title.textContent = 'Block IP Address';
    if (action) {
        action.textContent = 'Block IP';
        action.onclick = executeModalAction;
    }
    if (input) input.value = '';
    if (modal) modal.classList.add('show');
    if (input) input.focus();
}

function showWhitelistIPModal() {
    currentModalAction = 'whitelist';
    const modal = document.getElementById('ipModal');
    const title = document.getElementById('modalTitle');
    const action = document.getElementById('modalAction');
    const input = document.getElementById('ipInput');

    if (title) title.textContent = 'Whitelist IP Address';
    if (action) {
        action.textContent = 'Whitelist IP';
        action.onclick = executeModalAction;
    }
    if (input) input.value = '';
    if (modal) modal.classList.add('show');
    if (input) input.focus();
}

function closeModal() {
    const modal = document.getElementById('ipModal');
    if (modal) {
        modal.classList.remove('show');
    }
    currentModalAction = null;
}

function executeModalAction() {
    const input = document.getElementById('ipInput');
    const ip = input ? input.value.trim() : '';

    if (!ip) {
        showNotification('Please enter an IP address', 'error');
        return;
    }

    if (currentModalAction === 'block') {
        addToBlacklist(ip);
    } else if (currentModalAction === 'whitelist') {
        addToWhitelist(ip);
    }
    closeModal();
}

// ============================================
// Notifications
// ============================================

function showNotification(message, type = 'success') {
    console.log('Notification:', type, message);

    // Remove existing notifications
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" style="width: 20px; height: 20px;">
            ${type === 'success'
            ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><polyline points="22,4 12,14.01 9,11.01" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
            : '<circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/><line x1="15" y1="9" x2="9" y2="15" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="9" y1="9" x2="15" y2="15" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>'
        }
        </svg>
        <span>${message}</span>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// ============================================
// Keyboard Shortcuts
// ============================================

document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
        closeModal();
    }
});

document.addEventListener('click', function (e) {
    if (e.target.classList.contains('modal-overlay')) {
        closeModal();
    }
});

document.addEventListener('keypress', function (e) {
    if (e.key === 'Enter') {
        const target = e.target;
        if (target.id === 'blacklist-ip-input') {
            addToBlacklist();
        } else if (target.id === 'whitelist-ip-input') {
            addToWhitelist();
        } else if (target.id === 'ipInput') {
            executeModalAction();
        }
    }
});
