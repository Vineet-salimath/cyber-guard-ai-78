// ============================================
// MALWARESNIPPER - POPUP UI - ENHANCED
// Real-time Status with Symbol & Alert Managers
// ============================================

let scans = [];
let stats = {
  monitored: 0,
  threats: 0,
  status: 'SAFE',
  currentRisk: 0
};

// Track real-time updates
let alertStream = null;
let symbolStream = null;

// Status mapping based on risk score
const RISK_THRESHOLDS = {
  SAFE: { min: 0, max: 40, color: '#00ff88', bgColor: 'rgba(0, 255, 136, 0.1)', borderColor: 'rgba(0, 255, 136, 0.3)', icon: '✓' },
  SUSPICIOUS: { min: 40, max: 70, color: '#ffc107', bgColor: 'rgba(255, 193, 7, 0.1)', borderColor: 'rgba(255, 193, 7, 0.3)', icon: '⚠' },
  THREAT: { min: 70, max: 100, color: '#ff5252', bgColor: 'rgba(255, 82, 82, 0.1)', borderColor: 'rgba(255, 82, 82, 0.3)', icon: '✗' }
};

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  console.log('🛡️ Popup loaded with real-time managers');
  
  // Load saved data
  await loadStats();
  await loadRecentAlerts();
  
  // Update UI
  updateUI();
  
  // Setup event listeners
  setupEventListeners();
  
  // Check connection status
  checkConnectionStatus();
  
  // ============================================
  // REAL-TIME MESSAGE LISTENERS
  // ============================================
  
  // Listen for SYMBOL UPDATES (icon/status changes)
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SYMBOL_UPDATE') {
      console.log('🔄 Symbol update received:', message.symbol);
      handleSymbolUpdate(message);
    } 
    // Listen for ALERT UPDATES (new threats)
    else if (message.type === 'ALERT_UPDATE') {
      console.log('🚨 Alert update received:', message.alert.classification);
      handleAlertUpdate(message);
    }
    // Listen for ALERT STREAM (continuous updates)
    else if (message.type === 'ALERT_STREAM') {
      console.log('📡 Alert stream data:', message.data.alerts?.length || 0, 'alerts');
      handleAlertStream(message);
    }
    // Legacy SCAN_RESULT handling
    else if (message.type === 'SCAN_RESULT') {
      console.log('🎯 Scan result received:', message.riskScore);
      updateStatus(message.riskScore);
      loadStats().then(() => {
        loadRecentAlerts().then(() => {
          updateUI();
        });
      });
    } 
    else if (message.action === 'statsUpdated') {
      console.log('📊 Stats updated - refreshing UI');
      loadStats().then(() => {
        loadRecentAlerts().then(() => {
          updateUI();
        });
      });
    }
  });
  
  // ============================================
  // CONTINUOUS REAL-TIME UPDATE LOOP
  // ============================================
  
  // Auto-refresh every 2 seconds for real-time feel
  setInterval(async () => {
    await loadStats();
    await loadRecentAlerts();
    updateUI();
  }, 2000);
  
  // Check connection every 5 seconds
  setInterval(checkConnectionStatus, 5000);
});

// ============================================
// HANDLE SYMBOL UPDATES (Real-time icon changes)
// ============================================
async function handleSymbolUpdate(message) {
  const { symbol, symbolData, riskScore, classification } = message;
  
  console.log(`✨ Applying symbol: ${symbol}`);
  
  // Update status card with new symbol
  const statusCard = document.querySelector('.stat-card-safe');
  const statusValue = document.getElementById('statusText');
  
  if (statusCard && statusValue && symbolData) {
    // Smooth transition
    statusCard.style.transition = 'all 0.3s ease-in-out';
    statusValue.style.transition = 'all 0.3s ease-in-out';
    
    // Apply symbol colors
    statusCard.style.background = symbolData.bgColor;
    statusCard.style.borderColor = symbolData.borderColor;
    statusValue.style.color = symbolData.color;
    
    // Update text with emoji and symbol
    statusValue.innerHTML = `
      <span style="font-size: 1.2em; margin-right: 4px;">${symbolData.emoji}</span>
      <span>${symbolData.title}</span>
    `;
    
    // Add pulse animation for threats
    if (symbol === 'THREAT' || symbol === 'SCANNING') {
      statusCard.classList.add('pulse-animation');
    } else {
      statusCard.classList.remove('pulse-animation');
    }
    
    // Scale animation
    statusCard.style.transform = 'scale(1.05)';
    setTimeout(() => {
      statusCard.style.transform = 'scale(1)';
    }, 200);
  }
  
  // Update stats
  stats.status = symbol;
  stats.currentRisk = riskScore || 0;
  
  // Save updated stats
  await chrome.storage.local.set({ 
    stats: stats,
    currentRisk: riskScore || 0 
  });
}

// ============================================
// HANDLE ALERT UPDATES (Real-time alerts)
// ============================================
async function handleAlertUpdate(message) {
  const { alert } = message;
  
  console.log(`🚨 New alert: ${alert.classification} - ${alert.url}`);
  
  // Add to scans array at the beginning (most recent first)
  scans.unshift({
    url: alert.url,
    classification: alert.classification,
    risk_score: alert.risk_score,
    timestamp: alert.timestamp,
    severity: alert.severity,
    id: alert.id
  });
  
  // Keep only last 10 alerts
  scans = scans.slice(0, 10);
  
  // Re-render alerts section with animation
  const alertsList = document.getElementById('alertsList');
  if (alertsList) {
    // Add fade-in animation
    alertsList.style.animation = 'fadeIn 0.3s ease-in';
    setTimeout(() => {
      alertsList.style.animation = '';
    }, 300);
    
    renderAlerts();
  }
  
  // Update threat count if this is a threat
  if (alert.classification === 'MALICIOUS' || alert.classification === 'SUSPICIOUS') {
    stats.threats = (stats.threats || 0) + 1;
    document.getElementById('threatsCount').textContent = stats.threats;
  }
  
  // Update monitored count
  stats.monitored = (stats.monitored || 0) + 1;
  document.getElementById('monitoredCount').textContent = stats.monitored;
}

// ============================================
// HANDLE ALERT STREAM (Continuous updates)
// ============================================
function handleAlertStream(message) {
  const { data } = message;
  
  if (data.stats) {
    // Update statistics in real-time
    const stats_element = document.getElementById('threatStats');
    if (stats_element) {
      stats_element.innerHTML = `
        <div class="stat-detail">
          <span class="stat-label">Critical</span>
          <span class="stat-count critical">${data.stats.critical || 0}</span>
        </div>
        <div class="stat-detail">
          <span class="stat-label">High</span>
          <span class="stat-count high">${data.stats.high || 0}</span>
        </div>
        <div class="stat-detail">
          <span class="stat-label">Medium</span>
          <span class="stat-count medium">${data.stats.medium || 0}</span>
        </div>
      `;
    }
  }
}

// Load stats from storage
async function loadStats() {
  try {
    const result = await chrome.storage.local.get(['stats', 'scans', 'currentRisk', 'alertStats']);
    if (result.stats) {
      stats = result.stats;
    }
    if (result.scans) {
      scans = result.scans || [];
    }
    if (result.currentRisk !== undefined) {
      stats.currentRisk = result.currentRisk;
    }
  } catch (error) {
    console.error('Error loading stats:', error);
  }
}

// ============================================
// 🔥 REAL-TIME STATUS UPDATE FUNCTION
// ============================================
async function updateStatus(riskScore) {
  console.log(`🎯 Updating status for risk: ${riskScore}%`);
  
  // Determine status based on risk score
  let statusLabel = 'SAFE';
  let statusTheme = RISK_THRESHOLDS.SAFE;
  
  if (riskScore >= 70) {
    statusLabel = 'THREAT';
    statusTheme = RISK_THRESHOLDS.THREAT;
  } else if (riskScore >= 40) {
    statusLabel = 'SUSPICIOUS';
    statusTheme = RISK_THRESHOLDS.SUSPICIOUS;
  }
  
  // Update stats in memory
  stats.status = statusLabel;
  stats.currentRisk = riskScore;
  
  // Save to storage for persistence
  await chrome.storage.local.set({ 
    stats: stats,
    currentRisk: riskScore 
  });
  
  // 🎨 Update the status card immediately with animation
  const statusCard = document.querySelector('.stat-card-safe');
  const statusValue = document.getElementById('statusText');
  
  if (statusCard && statusValue) {
    // Apply smooth transitions
    statusCard.style.transition = 'all 0.3s ease-in-out';
    statusValue.style.transition = 'all 0.3s ease-in-out';
    
    // Update colors based on threshold
    statusCard.style.background = statusTheme.bgColor;
    statusCard.style.borderColor = statusTheme.borderColor;
    statusValue.style.color = statusTheme.color;
    statusValue.textContent = statusLabel;
    
    // Add subtle animation
    statusCard.style.transform = 'scale(1.02)';
    setTimeout(() => {
      statusCard.style.transform = 'scale(1)';
    }, 150);
  }
  
  console.log(`✅ Status updated to: ${statusLabel} (Risk: ${riskScore}%)`);
}

// Load recent alerts
async function loadRecentAlerts() {
  try {
    const result = await chrome.storage.local.get(['recentScans', 'alertQueue']);
    
    // Prefer newer alertQueue from AlertManager
    if (result.alertQueue && result.alertQueue.length > 0) {
      scans = result.alertQueue.slice(0, 10);
    } else if (result.recentScans) {
      scans = result.recentScans.slice(0, 10);
    }
  } catch (error) {
    console.error('Error loading alerts:', error);
  }
}

// Update UI with current data
function updateUI() {
  // Update stats counters with real-time values
  document.getElementById('monitoredCount').textContent = stats.monitored || 0;
  document.getElementById('threatsCount').textContent = stats.threats || 0;
  
  // Update status badge based on current risk
  const statusCard = document.querySelector('.stat-card-safe');
  const statusValue = document.getElementById('statusText');
  
  // Determine current status from risk score
  let currentStatus = stats.status || 'SAFE';
  let currentTheme = RISK_THRESHOLDS[currentStatus] || RISK_THRESHOLDS.SAFE;
  
  if (statusCard && statusValue) {
    statusCard.style.background = currentTheme.bgColor;
    statusCard.style.borderColor = currentTheme.borderColor;
    statusValue.style.color = currentTheme.color;
    
    // Show emoji with status
    statusValue.innerHTML = `
      <span style="font-size: 1.2em; margin-right: 4px;">${currentTheme.icon}</span>
      <span>${currentStatus}</span>
    `;
  }
  
  // Render alerts
  renderAlerts();
}

// Render alert items with real-time styling
function renderAlerts() {
  const alertsList = document.getElementById('alertsList');
  
  if (scans.length === 0) {
    alertsList.innerHTML = `
      <div class="alert-empty">
        <span>✓</span> No alerts - All systems safe
      </div>
    `;
    return;
  }
  
  alertsList.innerHTML = scans.map((scan, index) => {
    const statusClass = getStatusClass(scan.classification);
    const riskClass = getRiskClass(scan.risk_score);
    const timeAgo = getTimeAgo(scan.timestamp);
    const isNew = index === 0 ? 'new' : '';
    
    return `
      <div class="alert-item ${isNew}" style="animation-delay: ${index * 50}ms;">
        <div class="alert-header">
          <span class="alert-status ${statusClass}">${scan.classification || 'UNKNOWN'}</span>
          <span class="alert-risk ${riskClass}">Risk: ${scan.risk_score || 0}%</span>
          ${isNew ? '<span class="badge-new">NEW</span>' : ''}
        </div>
        <div class="alert-url" title="${scan.url}">${scan.url}</div>
        <div class="alert-footer">
          <span class="alert-time">${timeAgo}</span>
          <button class="btn-view-details" data-url="${scan.url}">Details</button>
        </div>
      </div>
    `;
  }).join('');
  
  // Add event listeners to View Details buttons
  document.querySelectorAll('.btn-view-details').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const url = e.target.dataset.url;
      openDashboardWithUrl(url);
    });
  });
}

// Get status class
function getStatusClass(classification) {
  const classMap = {
    'BENIGN': 'safe',
    'SUSPICIOUS': 'suspicious',
    'MALICIOUS': 'malicious'
  };
  return classMap[classification] || 'unknown';
}

// Get risk class
function getRiskClass(riskScore) {
  if (riskScore >= 70) return 'high';
  if (riskScore >= 40) return 'medium';
  return 'low';
}

// Get time ago string
function getTimeAgo(timestamp) {
  const now = Date.now();
  const time = new Date(timestamp).getTime();
  const diff = now - time;
  
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return 'Just now';
}

// Setup event listeners
function setupEventListeners() {
  // Protection toggle
  const protectionToggle = document.getElementById('protectionToggle');
  if (protectionToggle) {
    protectionToggle.addEventListener('change', async (e) => {
      const enabled = e.target.checked;
      await chrome.storage.local.set({ protectionEnabled: enabled });
      console.log('Protection:', enabled ? 'ON' : 'OFF');
    });
    
    // Load protection state
    chrome.storage.local.get(['protectionEnabled'], (result) => {
      protectionToggle.checked = result.protectionEnabled !== false;
    });
  }
  
  // Dashboard button
  const dashboardBtn = document.getElementById('dashboardBtn');
  if (dashboardBtn) {
    dashboardBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: 'http://localhost:8080/dashboard' });
    });
  }
  
  // Scan Now button
  const scanBtn = document.getElementById('scanNowBtn');
  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      scanBtn.textContent = 'Scanning...';
      scanBtn.disabled = true;
      
      try {
        // Get current tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        // Send scan request to background
        chrome.runtime.sendMessage(
          { action: 'scanCurrent' },
          (response) => {
            console.log('Scan result:', response);
            scanBtn.textContent = 'Scan Current Page';
            scanBtn.disabled = false;
            
            // Reload stats and alerts
            setTimeout(() => {
              loadStats().then(() => {
                loadRecentAlerts().then(() => {
                  updateUI();
                });
              });
            }, 1000);
          }
        );
      } catch (error) {
        console.error('Scan error:', error);
        scanBtn.textContent = 'Scan Current Page';
        scanBtn.disabled = false;
      }
    });
  }
}

// Check connection status
async function checkConnectionStatus() {
  try {
    const response = await fetch('http://localhost:5000/health');
    if (response.ok) {
      const dot = document.querySelector('.status-dot');
      const text = document.querySelector('.status-text');
      if (dot && text) {
        dot.style.background = '#00ff88';
        text.textContent = 'Connected';
        text.style.color = '#00ff88';
      }
    } else {
      throw new Error('Backend not responding');
    }
  } catch (error) {
    const dot = document.querySelector('.status-dot');
    const text = document.querySelector('.status-text');
    if (dot && text) {
      dot.style.background = '#ff5252';
      text.textContent = 'Disconnected';
      text.style.color = '#ff5252';
    }
  }
}

// Open dashboard with specific URL
function openDashboardWithUrl(url) {
  chrome.tabs.create({ 
    url: `http://localhost:8080/dashboard?url=${encodeURIComponent(url)}` 
  });
}

console.log('✅ Popup script loaded with real-time symbol and alert managers');
