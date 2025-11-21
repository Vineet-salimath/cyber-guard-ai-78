// ═══════════════════════════════════════════════════════════════════════════
// POPUP ENHANCED - Real-Time Threat Monitor with WebSocket Support
// ═══════════════════════════════════════════════════════════════════════════

const BACKEND_URL = 'http://localhost:8080';
const DASHBOARD_URL = 'http://localhost:8080';

// State management
let isBackendOnline = false;
let currentAlerts = [];
let statsData = {
    totalRequests: 0,
    threatsBlocked: 0,
    currentThreatLevel: 'SAFE'
};

// DOM elements
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const monitoringToggle = document.getElementById('monitoringToggle');
const alertsContainer = document.getElementById('alertsContainer');
const totalRequestsEl = document.getElementById('totalRequests');
const threatsBlockedEl = document.getElementById('threatsBlocked');
const currentThreatLevelEl = document.getElementById('currentThreatLevel');
const openDashboardBtn = document.getElementById('openDashboard');

// ═══════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', async () => {
    console.log('🛡️ Popup Enhanced initialized');
    
    // Check backend status
    await checkBackendStatus();
    
    // Load saved settings
    await loadSettings();
    
    // Load alerts from storage
    await loadAlerts();
    
    // Load statistics
    await loadStatistics();
    
    // Setup event listeners
    setupEventListeners();
    
    // Start periodic updates
    startPeriodicUpdates();
});

// ═══════════════════════════════════════════════════════════════════════════
// BACKEND STATUS CHECK
// ═══════════════════════════════════════════════════════════════════════════

async function checkBackendStatus() {
    try {
        const response = await fetch(`${BACKEND_URL}/health`, {
            method: 'GET',
            timeout: 3000
        });
        
        if (response.ok) {
            isBackendOnline = true;
            updateStatusIndicator(true);
        } else {
            isBackendOnline = false;
            updateStatusIndicator(false);
        }
    } catch (error) {
        console.warn('⚠️ Backend offline:', error);
        isBackendOnline = false;
        updateStatusIndicator(false);
    }
}

function updateStatusIndicator(online) {
    if (online) {
        statusDot.classList.remove('offline');
        statusDot.classList.add('online');
        statusText.textContent = 'Connected';
        statusText.style.color = '#00ff88';
    } else {
        statusDot.classList.remove('online');
        statusDot.classList.add('offline');
        statusText.textContent = 'Backend Offline';
        statusText.style.color = '#ff4444';
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LOAD SETTINGS
// ═══════════════════════════════════════════════════════════════════════════

async function loadSettings() {
    try {
        const result = await chrome.storage.local.get(['autoScanEnabled']);
        const enabled = result.autoScanEnabled !== false; // Default true
        monitoringToggle.checked = enabled;
        console.log('✅ Settings loaded: monitoring =', enabled);
    } catch (error) {
        console.error('❌ Error loading settings:', error);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LOAD ALERTS FROM STORAGE
// ═══════════════════════════════════════════════════════════════════════════

async function loadAlerts() {
    try {
        const result = await chrome.storage.local.get(['recentAlerts']);
        currentAlerts = result.recentAlerts || [];
        
        console.log('📥 Loaded alerts:', currentAlerts.length);
        renderAlerts();
    } catch (error) {
        console.error('❌ Error loading alerts:', error);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LOAD STATISTICS
// ═══════════════════════════════════════════════════════════════════════════

async function loadStatistics() {
    try {
        // Load from chrome.storage
        const result = await chrome.storage.local.get(['realtimeStats']);
        if (result.realtimeStats) {
            statsData = result.realtimeStats;
        }
        
        // Also try to fetch from backend if online
        if (isBackendOnline) {
            const response = await fetch(`${BACKEND_URL}/api/dashboard/stats`);
            if (response.ok) {
                const backendStats = await response.json();
                statsData = {
                    totalRequests: backendStats.total_requests || 0,
                    threatsBlocked: backendStats.malicious_detected || 0,
                    currentThreatLevel: calculateThreatLevel(backendStats)
                };
            }
        }
        
        updateStatistics();
    } catch (error) {
        console.error('❌ Error loading statistics:', error);
    }
}

function calculateThreatLevel(stats) {
    const total = stats.total_requests || 0;
    const malicious = stats.malicious_detected || 0;
    
    if (total === 0) return 'SAFE';
    
    const percentage = (malicious / total) * 100;
    
    if (percentage >= 10) return 'CRITICAL';
    if (percentage >= 5) return 'HIGH';
    if (percentage >= 1) return 'MEDIUM';
    return 'LOW';
}

function updateStatistics() {
    totalRequestsEl.textContent = statsData.totalRequests;
    threatsBlockedEl.textContent = statsData.threatsBlocked;
    currentThreatLevelEl.textContent = statsData.currentThreatLevel;
    
    // Color code threat level
    const colors = {
        'SAFE': '#00ff88',
        'LOW': '#ffcc00',
        'MEDIUM': '#ff8800',
        'HIGH': '#ff4444',
        'CRITICAL': '#ff0000'
    };
    currentThreatLevelEl.style.color = colors[statsData.currentThreatLevel] || '#00ff88';
}

// ═══════════════════════════════════════════════════════════════════════════
// RENDER ALERTS
// ═══════════════════════════════════════════════════════════════════════════

function renderAlerts() {
    if (currentAlerts.length === 0) {
        alertsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">🛡️</div>
                <p>No threats detected</p>
                <p style="font-size: 12px; margin-top: 8px;">Your browsing is secure</p>
            </div>
        `;
        return;
    }
    
    // Sort alerts by timestamp (newest first)
    const sortedAlerts = [...currentAlerts].sort((a, b) => b.timestamp - a.timestamp);
    
    // Limit to last 10 alerts
    const recentAlerts = sortedAlerts.slice(0, 10);
    
    alertsContainer.innerHTML = recentAlerts.map(alert => {
        const severity = getSeverity(alert.riskScore || alert.overall_risk_score || 0);
        const threatType = alert.threat_level || alert.threatLevel || 'Unknown';
        const timestamp = formatTimestamp(alert.timestamp);
        
        return `
            <div class="alert-item ${severity}" data-alert-id="${alert.id || alert.url_hash}" data-url="${alert.url}">
                <div class="alert-header">
                    <span class="threat-badge ${severity}">${threatType}</span>
                    <span class="risk-score">Risk: ${Math.round(alert.riskScore || alert.overall_risk_score || 0)}%</span>
                </div>
                <div class="alert-url" title="${alert.url}">${truncateUrl(alert.url, 45)}</div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span class="alert-time">${timestamp}</span>
                    <button class="btn-view-details" data-alert-id="${alert.id || alert.url_hash}">View Details</button>
                </div>
            </div>
        `;
    }).join('');
    
    // Add click listeners to View Details buttons
    document.querySelectorAll('.btn-view-details').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const alertId = btn.getAttribute('data-alert-id');
            openAlertDetails(alertId);
        });
    });
    
    // Add click listeners to alert items
    document.querySelectorAll('.alert-item').forEach(item => {
        item.addEventListener('click', () => {
            const alertId = item.getAttribute('data-alert-id');
            openAlertDetails(alertId);
        });
    });
}

function getSeverity(riskScore) {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 30) return 'medium';
    return 'low';
}

function truncateUrl(url, maxLength) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
}

// ═══════════════════════════════════════════════════════════════════════════
// OPEN ALERT DETAILS
// ═══════════════════════════════════════════════════════════════════════════

function openAlertDetails(alertId) {
    const alert = currentAlerts.find(a => (a.id || a.url_hash) === alertId);
    if (!alert) {
        console.error('❌ Alert not found:', alertId);
        return;
    }
    
    const url = alert.url;
    const timestamp = alert.timestamp;
    const encodedUrl = encodeURIComponent(url);
    
    // Open dashboard with alert details
    const dashboardUrl = `${DASHBOARD_URL}/?alertId=${alertId}&timestamp=${timestamp}&url=${encodedUrl}`;
    
    chrome.tabs.create({ url: dashboardUrl }, (tab) => {
        console.log('✅ Opened dashboard for alert:', alertId);
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// EVENT LISTENERS
// ═══════════════════════════════════════════════════════════════════════════

function setupEventListeners() {
    // Monitoring toggle
    monitoringToggle.addEventListener('change', async (e) => {
        const enabled = e.target.checked;
        await chrome.storage.local.set({ autoScanEnabled: enabled });
        console.log('✅ Monitoring', enabled ? 'enabled' : 'disabled');
        
        // Notify background script
        chrome.runtime.sendMessage({
            type: 'TOGGLE_MONITORING',
            enabled: enabled
        });
    });
    
    // Open dashboard button
    openDashboardBtn.addEventListener('click', () => {
        chrome.tabs.create({ url: DASHBOARD_URL }, (tab) => {
            console.log('✅ Opened dashboard');
        });
    });
    
    // Listen for updates from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.type === 'NEW_ALERT') {
            console.log('🚨 New alert received in popup:', message.alert);
            handleNewAlert(message.alert);
        } else if (message.type === 'STATS_UPDATE') {
            console.log('📊 Stats update received:', message.stats);
            statsData = message.stats;
            updateStatistics();
        }
    });
    
    // Listen for storage changes
    chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === 'local') {
            if (changes.recentAlerts) {
                console.log('🔄 Alerts updated in storage');
                currentAlerts = changes.recentAlerts.newValue || [];
                renderAlerts();
            }
            if (changes.realtimeStats) {
                console.log('🔄 Stats updated in storage');
                statsData = changes.realtimeStats.newValue || statsData;
                updateStatistics();
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// HANDLE NEW ALERT
// ═══════════════════════════════════════════════════════════════════════════

function handleNewAlert(alert) {
    // Add to current alerts
    currentAlerts.unshift(alert);
    
    // Keep only last 50 alerts
    if (currentAlerts.length > 50) {
        currentAlerts = currentAlerts.slice(0, 50);
    }
    
    // Update UI
    renderAlerts();
    
    // Update stats
    statsData.threatsBlocked++;
    updateStatistics();
    
    // Update badge
    chrome.action.setBadgeText({ text: statsData.threatsBlocked.toString() });
    chrome.action.setBadgeBackgroundColor({ color: '#ff4444' });
}

// ═══════════════════════════════════════════════════════════════════════════
// PERIODIC UPDATES
// ═══════════════════════════════════════════════════════════════════════════

function startPeriodicUpdates() {
    // Check backend status every 10 seconds
    setInterval(checkBackendStatus, 10000);
    
    // Refresh statistics every 5 seconds
    setInterval(loadStatistics, 5000);
    
    // Refresh alerts every 30 seconds
    setInterval(loadAlerts, 30000);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORT FOR TESTING
// ═══════════════════════════════════════════════════════════════════════════

console.log('✅ Popup Enhanced script loaded');
