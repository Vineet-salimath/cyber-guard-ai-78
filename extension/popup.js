// ============================================
// MALWARESNIPPER - POPUP UI
// ============================================

let scans = [];
let stats = {
  monitored: 0,
  threats: 0,
  status: 'SAFE'
};

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  console.log('🛡️ Popup loaded');
  
  // Load saved data
  await loadStats();
  await loadRecentAlerts();
  
  // Update UI
  updateUI();
  
  // Setup event listeners
  setupEventListeners();
  
  // Check connection status
  checkConnectionStatus();
  
  // Listen for real-time updates from background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'statsUpdated') {
      console.log('📊 Stats updated - refreshing UI');
      loadStats().then(() => {
        loadRecentAlerts().then(() => {
          updateUI();
        });
      });
    }
  });
  
  // Auto-refresh every 5 seconds to show live data
  setInterval(async () => {
    await loadStats();
    await loadRecentAlerts();
    updateUI();
  }, 5000);
});

// Load stats from storage
async function loadStats() {
  try {
    const result = await chrome.storage.local.get(['stats', 'scans']);
    if (result.stats) {
      stats = result.stats;
    }
    if (result.scans) {
      scans = result.scans || [];
    }
  } catch (error) {
    console.error('Error loading stats:', error);
  }
}

// Load recent alerts
async function loadRecentAlerts() {
  try {
    const result = await chrome.storage.local.get(['recentScans']);
    if (result.recentScans) {
      scans = result.recentScans.slice(0, 5); // Last 5 alerts
    }
  } catch (error) {
    console.error('Error loading alerts:', error);
  }
}

// Update UI with current data
function updateUI() {
  // Update stats
  document.getElementById('monitoredCount').textContent = stats.monitored || 0;
  document.getElementById('threatsCount').textContent = stats.threats || 0;
  document.getElementById('statusText').textContent = stats.status || 'SAFE';
  
  // Update status card color
  const statusCard = document.querySelector('.stat-card-safe');
  const statusValue = document.getElementById('statusText');
  if (stats.threats > 0) {
    statusCard.style.background = 'rgba(255, 82, 82, 0.1)';
    statusCard.style.borderColor = 'rgba(255, 82, 82, 0.3)';
    statusValue.style.color = '#ff5252';
    statusValue.textContent = 'THREAT';
  } else {
    statusCard.style.background = 'rgba(0, 255, 136, 0.1)';
    statusCard.style.borderColor = 'rgba(0, 255, 136, 0.3)';
    statusValue.style.color = '#00ff88';
    statusValue.textContent = 'SAFE';
  }
  
  // Render alerts
  renderAlerts();
}

// Render alert items
function renderAlerts() {
  const alertsList = document.getElementById('alertsList');
  
  if (scans.length === 0) {
    alertsList.innerHTML = `
      <div class="alert-empty">
        No alerts in the last 24 hours
      </div>
    `;
    return;
  }
  
  alertsList.innerHTML = scans.map(scan => {
    const statusClass = getStatusClass(scan.classification);
    const riskClass = getRiskClass(scan.risk_score);
    const timeAgo = getTimeAgo(scan.timestamp);
    
    return `
      <div class="alert-item">
        <div class="alert-header">
          <span class="alert-status ${statusClass}">${scan.classification || 'UNKNOWN'}</span>
          <span class="alert-risk ${riskClass}">Risk: ${scan.risk_score || 0}%</span>
        </div>
        <div class="alert-url" title="${scan.url}">${scan.url}</div>
        <div class="alert-footer">
          <span class="alert-time">${timeAgo}</span>
          <button class="btn-view-details" data-url="${scan.url}">View Details</button>
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
  protectionToggle.addEventListener('change', async (e) => {
    const enabled = e.target.checked;
    await chrome.storage.local.set({ protectionEnabled: enabled });
    console.log('Protection:', enabled ? 'ON' : 'OFF');
  });
  
  // Load protection state
  chrome.storage.local.get(['protectionEnabled'], (result) => {
    protectionToggle.checked = result.protectionEnabled !== false;
  });
  
  // Dashboard button
  document.getElementById('dashboardBtn').addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://localhost:8080/dashboard' });
  });
  
  // Scan Now button
  document.getElementById('scanNowBtn').addEventListener('click', async () => {
    const btn = document.getElementById('scanNowBtn');
    btn.textContent = 'Scanning...';
    btn.disabled = true;
    
    try {
      // Get current tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      // Send scan request to background
      chrome.runtime.sendMessage(
        { action: 'scanCurrent' },
        (response) => {
          console.log('Scan result:', response);
          btn.textContent = 'Scan Current Page';
          btn.disabled = false;
          
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
      btn.textContent = 'Scan Current Page';
      btn.disabled = false;
    }
  });
}

// Check connection status
async function checkConnectionStatus() {
  try {
    const response = await fetch('http://localhost:5000/health');
    if (response.ok) {
      document.querySelector('.status-dot').style.background = '#00ff88';
      document.querySelector('.status-text').textContent = 'Connected';
      document.querySelector('.status-text').style.color = '#00ff88';
    } else {
      throw new Error('Backend not responding');
    }
  } catch (error) {
    document.querySelector('.status-dot').style.background = '#ff5252';
    document.querySelector('.status-text').textContent = 'Disconnected';
    document.querySelector('.status-text').style.color = '#ff5252';
  }
}

// Open dashboard with specific URL
function openDashboardWithUrl(url) {
  chrome.tabs.create({ 
    url: `http://localhost:8080/dashboard?url=${encodeURIComponent(url)}` 
  });
}

// Listen for updates from background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'statsUpdated') {
    loadStats().then(() => {
      loadRecentAlerts().then(() => {
        updateUI();
      });
    });
  }
});

// Refresh stats every 10 seconds
setInterval(() => {
  loadStats().then(() => {
    loadRecentAlerts().then(() => {
      updateUI();
    });
  });
  checkConnectionStatus();
}, 10000);
