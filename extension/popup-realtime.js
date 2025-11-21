// MALWARE SNIPPER - ENHANCED REAL-TIME POPUP
// Shows live threat status with broadcast channel integration

let currentTab = null;
let currentScanResult = null;
let broadcastChannel = null;
let isSubscribed = false;

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  console.log('🚀 [POPUP] Initializing MalwareSnipper popup...');
  await initializeBroadcastChannel();
  await loadCurrentTab();
  setupEventListeners();
  console.log('✅ [POPUP] Initialization complete');
});

// Initialize BroadcastChannel for real-time updates
async function initializeBroadcastChannel() {
  try {
    broadcastChannel = new BroadcastChannel('malware-snipper-updates');
    
    broadcastChannel.onmessage = (event) => {
      handleRealtimeUpdate(event.data);
    };
    
    console.log('📡 Popup connected to real-time updates');
    isSubscribed = true;
    
    // Update connection indicator
    const indicator = document.getElementById('connectionIndicator');
    if (indicator) {
      indicator.textContent = '🟢 Live';
      indicator.className = 'connection-status live';
    }
    
  } catch (error) {
    console.error('Failed to initialize broadcast channel:', error);
    const indicator = document.getElementById('connectionIndicator');
    if (indicator) {
      indicator.textContent = '🔴 Offline';
      indicator.className = 'connection-status offline';
    }
  }
}

// Handle real-time updates from background worker
function handleRealtimeUpdate(message) {
  console.log('📨 Popup received update:', message);
  
  if (message.type === 'scan_complete' && message.data) {
    // Check if this update is for current tab
    if (currentTab && message.data.url === currentTab.url) {
      currentScanResult = {
        url: message.data.url,
        threatLevel: message.data.threatLevel,
        riskScore: message.data.riskScore,
        stats: message.data.stats,
        threatNames: message.data.threatNames || [],
        timestamp: message.data.timestamp
      };
      displayScanResult(currentScanResult);
    }
  }
  
  if (message.type === 'stats_update') {
    updateStatsDisplay(message.data);
  }
}

// Setup event listeners
function setupEventListeners() {
  const viewDetailsBtn = document.getElementById('viewDetailsBtn');
  const manualScanBtn = document.getElementById('manualScanBtn');
  const refreshBtn = document.getElementById('refreshBtn');
  
  if (viewDetailsBtn) {
    viewDetailsBtn.addEventListener('click', openDashboard);
  }
  
  if (manualScanBtn) {
    manualScanBtn.addEventListener('click', manualScan);
  }
  
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      loadCurrentTab();
    });
  }
}

// Load current tab and check for cached scan
async function loadCurrentTab() {
  console.log('🔍 Loading current tab information...');
  
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tabs[0];
  
  if (!currentTab || !currentTab.url) {
    console.log('❌ No active tab found');
    document.getElementById('currentUrl').textContent = 'No active tab';
    updateBadge('UNKNOWN', 'No active page');
    return;
  }
  
  console.log('✅ Current tab URL:', currentTab.url);
  
  // Skip chrome:// and extension URLs
  if (currentTab.url.startsWith('chrome://') || currentTab.url.startsWith('chrome-extension://')) {
    document.getElementById('currentUrl').textContent = 'Chrome system page';
    updateBadge('UNKNOWN', 'Cannot scan system pages');
    return;
  }
  
  // Display URL (hostname + path only)
  const urlDisplay = document.getElementById('currentUrl');
  try {
    const url = new URL(currentTab.url);
    urlDisplay.textContent = url.hostname + url.pathname;
    urlDisplay.title = currentTab.url; // Full URL on hover
  } catch (e) {
    urlDisplay.textContent = currentTab.url;
  }
  
  // Request scan result from background worker
  console.log('📡 Requesting scan result from background worker...');
  chrome.runtime.sendMessage({ 
    action: 'getCurrentScan',
    url: currentTab.url 
  }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('❌ Error getting scan:', chrome.runtime.lastError.message);
      updateBadge('UNKNOWN', 'Extension not ready');
      return;
    }
    
    if (response && response.result) {
      console.log('✅ Received scan result:', response.result);
      currentScanResult = response.result;
      displayCachedResult(response.result);
    } else {
      console.log('⏳ No cached result, checking storage...');
      // Fallback: Check storage
      chrome.storage.local.get(['autoScanHistory'], (result) => {
        const history = result.autoScanHistory || [];
        console.log('📚 Found', history.length, 'scans in history');
        const cached = history.find(scan => scan.url === currentTab.url);
        
        if (cached) {
          console.log('✅ Found cached scan:', cached.threatLevel);
          currentScanResult = cached;
          displayCachedResult(cached);
        } else {
          console.log('⏳ No cache found, showing scanning state...');
          updateBadge('SCANNING', 'Scanning in progress...');
          
          // Trigger a fresh scan
          setTimeout(() => {
            chrome.runtime.sendMessage({
              action: 'scanUrl',
              url: currentTab.url
            }, (scanResponse) => {
              if (scanResponse && scanResponse.result) {
                console.log('✅ Fresh scan complete:', scanResponse.result);
                displayScanResult(scanResponse.result);
              }
            });
          }, 500);
        }
      });
    }
  });
}

// Display cached scan result
function displayCachedResult(scan) {
  console.log('📋 Displaying cached result:', scan);
  
  const threatLevel = (scan.threatLevel || scan.threat_level || 'UNKNOWN').toUpperCase();
  const riskScore = scan.riskScore || scan.overall_risk_score || 0;
  
  updateBadge(threatLevel, getBadgeMessage(threatLevel, riskScore));
  
  // Update last scan time
  const lastScanEl = document.getElementById('lastScan');
  if (lastScanEl && scan.timestamp) {
    const timeDiff = Date.now() - scan.timestamp;
    const minutesAgo = Math.floor(timeDiff / 60000);
    lastScanEl.textContent = minutesAgo < 1 ? 'Just now' : `${minutesAgo}m ago`;
  }
  
  // Show threat details for non-safe sites
  if (threatLevel === 'SUSPICIOUS' || threatLevel === 'MALICIOUS') {
    const viewDetailsBtn = document.getElementById('viewDetailsBtn');
    if (viewDetailsBtn) {
      viewDetailsBtn.style.display = 'block';
    }
    
    const threatDetails = document.getElementById('threatDetails');
    if (threatDetails && scan.stats) {
      threatDetails.style.display = 'block';
      threatDetails.innerHTML = `
        <div class="threat-stats">
          <div class="stat-item">
            <span class="stat-label">🔴 Malicious:</span>
            <span class="stat-value">${scan.stats.malicious || 0}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">⚠️ Suspicious:</span>
            <span class="stat-value">${scan.stats.suspicious || 0}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">✅ Clean:</span>
            <span class="stat-value">${scan.stats.harmless || scan.stats.undetected || 0}</span>
          </div>
        </div>
      `;
    }
  } else {
    const viewDetailsBtn = document.getElementById('viewDetailsBtn');
    if (viewDetailsBtn) {
      viewDetailsBtn.style.display = 'none';
    }
    const threatDetails = document.getElementById('threatDetails');
    if (threatDetails) {
      threatDetails.style.display = 'none';
    }
  }
}

// Display fresh scan result
function displayScanResult(result) {
  console.log('🆕 Displaying fresh scan result:', result);
  
  const threatLevel = (result.threatLevel || result.threat_level || 'UNKNOWN').toUpperCase();
  const riskScore = result.riskScore || result.overall_risk_score || 0;
  
  updateBadge(threatLevel, getBadgeMessage(threatLevel, riskScore));
  
  // Update timestamp
  const lastScanEl = document.getElementById('lastScan');
  if (lastScanEl) {
    lastScanEl.textContent = 'Just now';
  }
  
  // Show "View Full Details" button for SUSPICIOUS or MALICIOUS
  if (threatLevel === 'SUSPICIOUS' || threatLevel === 'MALICIOUS') {
    const viewDetailsBtn = document.getElementById('viewDetailsBtn');
    if (viewDetailsBtn) {
      viewDetailsBtn.style.display = 'block';
    }
    
    const threatDetails = document.getElementById('threatDetails');
    if (threatDetails && result.stats) {
      threatDetails.style.display = 'block';
      threatDetails.innerHTML = `
        <div class="threat-stats">
          <div class="stat-item">
            <span class="stat-label">🔴 Malicious:</span>
            <span class="stat-value">${result.stats.malicious || 0}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">⚠️ Suspicious:</span>
            <span class="stat-value">${result.stats.suspicious || 0}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">✅ Clean:</span>
            <span class="stat-value">${result.stats.harmless || 0}</span>
          </div>
        </div>
      `;
    }
  }
}

// Scan current page manually
async function manualScan() {
  if (!currentTab || !currentTab.url) return;
  
  updateBadge('SCANNING', 'Scanning page...');
  
  const scanBtn = document.getElementById('manualScanBtn');
  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="spinner"></span> Scanning...';
  }
  
  // Request scan from background script
  chrome.runtime.sendMessage(
    { action: 'scanUrl', url: currentTab.url },
    (response) => {
      if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.innerHTML = '🔄 Scan Again';
      }
      
      if (response && response.result) {
        currentScanResult = {
          url: currentTab.url,
          threatLevel: response.result.threat_level,
          riskScore: response.result.overall_risk_score,
          stats: response.result.stats,
          threatNames: response.result.threat_names || [],
          timestamp: Date.now()
        };
        displayScanResult(currentScanResult);
      } else {
        updateBadge('UNKNOWN', 'Scan failed. Try again.');
      }
    }
  );
}

// Update badge display
function updateBadge(threatLevel, message) {
  const badge = document.getElementById('threatBadge');
  const messageEl = document.getElementById('threatMessage');
  
  if (!badge || !messageEl) return;
  
  const badgeConfig = {
    'SAFE': {
      emoji: '🟢',
      text: 'SAFE',
      className: 'threat-badge safe',
      message: message || 'No threats detected'
    },
    'SUSPICIOUS': {
      emoji: '🟡',
      text: 'SUSPICIOUS',
      className: 'threat-badge suspicious',
      message: message || 'Potential threats detected'
    },
    'MALICIOUS': {
      emoji: '🔴',
      text: 'MALICIOUS',
      className: 'threat-badge malicious',
      message: message || 'DANGER! Do not enter personal info'
    },
    'SCANNING': {
      emoji: '🔵',
      text: 'SCANNING',
      className: 'threat-badge scanning',
      message: message || 'Analyzing website...'
    },
    'UNKNOWN': {
      emoji: '⚪',
      text: 'UNKNOWN',
      className: 'threat-badge unknown',
      message: message || 'Unable to scan'
    }
  };
  
  const config = badgeConfig[threatLevel] || badgeConfig['UNKNOWN'];
  
  badge.innerHTML = `${config.emoji} ${config.text}`;
  badge.className = config.className;
  messageEl.textContent = config.message;
}

// Get badge message with risk score
function getBadgeMessage(threatLevel, riskScore) {
  const messages = {
    'SAFE': `Risk Score: ${riskScore.toFixed(1)}% - Site is clean`,
    'SUSPICIOUS': `Risk Score: ${riskScore.toFixed(1)}% - Exercise caution`,
    'MALICIOUS': `Risk Score: ${riskScore.toFixed(1)}% - DANGEROUS!`
  };
  
  return messages[threatLevel] || 'Unknown status';
}

// Update stats display
function updateStatsDisplay(stats) {
  const statsContainer = document.getElementById('globalStats');
  if (statsContainer && stats) {
    statsContainer.innerHTML = `
      <div class="global-stats">
        <div class="stat-item">
          <span class="stat-label">Total:</span>
          <span class="stat-value">${stats.totalScans || 0}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">Safe:</span>
          <span class="stat-value">${stats.safeSites || 0}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">Threats:</span>
          <span class="stat-value">${(stats.suspiciousSites || 0) + (stats.maliciousSites || 0)}</span>
        </div>
      </div>
    `;
  }
}

// Open dashboard
function openDashboard() {
  const encodedUrl = encodeURIComponent(currentTab.url);
  const dashboardUrl = `http://localhost:8081/dashboard?url=${encodedUrl}`;
  chrome.tabs.create({ url: dashboardUrl });
}

// Cleanup on popup close
window.addEventListener('unload', () => {
  if (broadcastChannel) {
    broadcastChannel.close();
  }
});

console.log('🛡️ Malware Snipper Popup Loaded - Real-Time Mode Active');
