/**
 * SIEM-Lite Console - Frontend JavaScript
 * Common utilities and helpers used across all pages.
 */

const SIEM = {
    // API base URL
    apiBase: '/api',

    // API request helper
    async request(endpoint, options = {}) {
        const url = endpoint.startsWith('http') ? endpoint : this.apiBase + endpoint;
        const defaults = {
            headers: { 'Content-Type': 'application/json' },
        };
        const config = { ...defaults, ...options };
        if (config.body && typeof config.body === 'object') {
            config.body = JSON.stringify(config.body);
        }
        try {
            const response = await fetch(url, config);
            if (!response.ok) {
                const error = await response.json().catch(() => ({ error: response.statusText }));
                throw new Error(error.error || `HTTP ${response.status}`);
            }
            return await response.json();
        } catch (err) {
            console.error(`API request failed: ${endpoint}`, err);
            throw err;
        }
    },

    // Format timestamp
    formatTime(ts) {
        if (!ts) return '-';
        const d = new Date(ts);
        if (isNaN(d)) return ts;
        return d.toLocaleString();
    },

    // Format relative time
    timeAgo(ts) {
        if (!ts) return 'never';
        const now = Date.now();
        const then = new Date(ts).getTime();
        if (isNaN(then)) return ts;
        const diff = Math.floor((now - then) / 1000);
        if (diff < 60) return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    },

    // Severity color class
    severityClass(sev) {
        const map = {
            critical: 'badge-critical', high: 'badge-high',
            medium: 'badge-medium', low: 'badge-low', info: 'badge-info',
            emergency: 'badge-critical', alert: 'badge-critical',
            error: 'badge-high', warning: 'badge-medium',
            notice: 'badge-low', debug: 'badge-info',
        };
        return map[String(sev || '').toLowerCase()] || 'badge-info';
    },

    // Escape HTML
    escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    },

    // Debounce function
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // Show notification (black & white design)
    notify(message, type = 'info') {
        const notif = document.createElement('div');
        notif.textContent = message;
        var bg, fg, border;
        if (type === 'error') {
            bg = '#fff'; fg = '#000'; border = '#000';
        } else if (type === 'success') {
            bg = '#000'; fg = '#fff'; border = '#000';
        } else {
            bg = '#fff'; fg = '#000'; border = '#000';
        }
        notif.style.cssText = `
            position: fixed; top: 80px; right: 24px; z-index: 9999;
            padding: 10px 18px; border-radius: 2px;
            background: ${bg}; color: ${fg};
            border: 1px solid ${border};
            font-family: "SF Pro Display", -apple-system, sans-serif;
            font-size: 0.6875rem; font-weight: 600;
            text-transform: uppercase; letter-spacing: 0.08em;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transition: all 0.25s ease;
            transform: translateX(100%);
            opacity: 0;
        `;
        document.body.appendChild(notif);
        requestAnimationFrame(function(){
            notif.style.transform = 'translateX(0)';
            notif.style.opacity = '1';
        });
        setTimeout(() => {
            notif.style.opacity = '0';
            notif.style.transform = 'translateX(100%)';
            setTimeout(() => notif.remove(), 300);
        }, 2500);
    },

    // Copy to clipboard
    copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.notify('Copied to clipboard', 'success');
        }).catch(() => {
            this.notify('Failed to copy', 'error');
        });
    },

    // Format bytes
    formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // Format number with commas
    formatNumber(num) {
        return new Intl.NumberFormat().format(num || 0);
    },

    // Get URL parameter
    getParam(name) {
        const params = new URLSearchParams(window.location.search);
        return params.get(name);
    },
};

// Export for use in other scripts
window.SIEM = SIEM;
