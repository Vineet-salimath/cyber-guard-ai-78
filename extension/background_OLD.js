// ═══════════════════════════════════════════════════════════════════════════
// MALWARE SNIPPER - EXTENSION BACKGROUND SERVICE
// STRICT PIPELINE: Extension → Backend ONLY (Dashboard just displays results)
// ═══════════════════════════════════════════════════════════════════════════

const BACKEND_URL = 'http://localhost:5000';
const DASHBOARD_URL = 'http://localhost:8082';

// Blocked URL patterns (never send these to backend)
const BLOCKED_PATTERNS = [
  /^chrome:\/\//,
  /^chrome-extension:\/\//,
  /^about:/,
  /^file:\/\//,
  /^http:\/\/localhost:8082/i,  // Block dashboard's own URL
  /^http:\/\/127\.0\.0\.1:8082/i,  // Block localhost variants
  /^http:\/\/localhost:5000/i,  // Block backend's own URL
  /^http:\/\/127\.0\.0\.1:5000/i,
  /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)(\?|$)/i,
  /\/(ads?|analytics?|tracking?|pixel|beacon)/i,
  /\/favicon\.ico$/i,
  /\/manifest\.json$/i,
  /doubleclick\.net/i,
  /googlesyndication\./i,
  /google-analytics\./i,
  /\.doubleclick\./i,
];

// Scan cooldown to prevent duplicate submissions
const recentScans = new Map(); // url -> timestamp
const SCAN_COOLDOWN = 5000; // 5 seconds

// ═══════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

chrome.runtime.onInstalled.addListener(() => {
  console.log('🛡️ MalwareSnipper Extension Installed');
  console.log('📡 NEW PIPELINE: Extension → Backend → Dashboard');
  console.log('🔗 Backend URL:', BACKEND_URL);
  
  // Initialize storage
  chrome.storage.local.set({
    autoScanEnabled: true,
    notificationsEnabled: true,
    extensionStats: {
      urlsCaptured: 0,
      urlsSent: 0,
      urlsBlocked: 0
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// URL VALIDATION - Block unwanted URLs before sending
// ═══════════════════════════════════════════════════════════════════════════

function shouldScanURL(url) {
  if (!url || typeof url !== 'string') {
    return false;
  }

  // Must be HTTP or HTTPS
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return false;
  }

  // Check blocked patterns
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(url)) {
      console.log(`⛔ [BLOCKED] Skipping: ${url.substring(0, 100)}`);
      incrementStat('urlsBlocked');
      return false;
    }
  }

  // Check cooldown
  const lastScan = recentScans.get(url);
  if (lastScan && (Date.now() - lastScan) < SCAN_COOLDOWN) {
    console.log(`⏭️ [COOLDOWN] Skipping: ${url.substring(0, 50)} (scanned ${((Date.now() - lastScan) / 1000).toFixed(1)}s ago)`);
    return false;
  }

  return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// SEND URL TO BACKEND - Core function (DIRECT TO BACKEND, NOT DASHBOARD)
// ═══════════════════════════════════════════════════════════════════════════

async function sendURLToBackend(url) {
  try {
    // Update cooldown
    recentScans.set(url, Date.now());
    
    console.log(`📤 [BACKEND] Sending URL directly to backend: ${url.substring(0, 80)}`);
    
    // Prepare payload
    const payload = {
      url: url,
      timestamp: Date.now(),
      source: 'extension',
      user_agent: navigator.userAgent
    };
    
    // Send directly to backend /api/scan
    const response = await fetch(`${BACKEND_URL}/api/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'chrome-extension://' + chrome.runtime.id
      },
      body: JSON.stringify(payload)
    });
    
    if (response.ok) {
      const result = await response.json();
      console.log(`✅ [BACKEND] Scan accepted:`, result);
      incrementStat('urlsSent');
      
      // Show notification if threat detected
      if (result.risk !== 'safe' && result.risk !== 'benign') {
        showThreatNotification(url, result);
      }
    } else {
      const errorText = await response.text();
      console.error(`❌ [BACKEND] Scan rejected (${response.status}):`, errorText);
    }
    
  } catch (error) {
    console.error(`❌ [BACKEND] Error sending URL to backend:`, error);
  }
}

// Threat notification helper
function showThreatNotification(url, result) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '⚠️ Threat Detected!',
    message: `${url}\nRisk: ${result.risk}\nScore: ${result.score}/100`,
    priority: 2
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// NAVIGATION CAPTURE - Detect when user visits websites
// ═══════════════════════════════════════════════════════════════════════════

// Primary: webNavigation.onCommitted (fires when navigation commits)
chrome.webNavigation.onCommitted.addListener((details) => {
  // Only process main frame (actual page navigation, not iframes)
  if (details.frameId !== 0) {
    return;
  }
  
  const url = details.url;
  
  // CRITICAL: Block dashboard URLs IMMEDIATELY
  if (url.includes('localhost:8082') || url.includes('127.0.0.1:8082')) {
    console.log(`⛔ [BLOCKED] Ignoring dashboard URL: ${url.substring(0, 80)}`);
    return;
  }
  
  incrementStat('urlsCaptured');
  
  if (shouldScanURL(url)) {
    console.log(`🌐 [NAVIGATION] User visited: ${url.substring(0, 80)}`);
    sendURLToBackend(url);  // CHANGED: Send directly to backend
  }
});

// Secondary: tabs.onUpdated (backup for cases webNavigation misses)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only process when URL changes and page is loading
  if (changeInfo.status === 'loading' && changeInfo.url) {
    const url = changeInfo.url;
    
    // CRITICAL: Block dashboard URLs IMMEDIATELY
    if (url.includes('localhost:8082') || url.includes('127.0.0.1:8082')) {
      console.log(`⛔ [BLOCKED] Ignoring dashboard URL in tab update: ${url.substring(0, 80)}`);
      return;
    }
    
    incrementStat('urlsCaptured');
    
    if (shouldScanURL(url)) {
      console.log(`🔄 [TAB UPDATE] URL changed: ${url.substring(0, 80)}`);
      sendURLToBackend(url);  // CHANGED: Send directly to backend
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// STATISTICS TRACKING
// ═══════════════════════════════════════════════════════════════════════════
    const storage = await chrome.storage.local.get(['urlQueue']);
    const queue = storage.urlQueue || [];
    
    if (queue.length === 0) {
      return;
    }
    
    console.log(`📦 [QUEUE] Processing ${queue.length} queued URLs...`);
    
    for (const item of queue) {
      await sendURLToDashboard(item.url);
      await new Promise(resolve => setTimeout(resolve, 100)); // Small delay between sends
    }
    
    // Clear queue
    await chrome.storage.local.set({ urlQueue: [] });
    console.log(`✅ [QUEUE] All queued URLs processed`);
    
  } catch (error) {
    console.error('❌ [QUEUE] Error processing queue:', error);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// DASHBOARD CONNECTION - Detect when dashboard opens and process queue
// ═══════════════════════════════════════════════════════════════════════════

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith(DASHBOARD_URL)) {
    console.log('🎯 [DASHBOARD] Dashboard opened - processing queue...');
    // Wait a bit for dashboard to initialize
    setTimeout(() => {
      processQueuedURLs();
    }, 2000);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// STATISTICS TRACKING
// ═══════════════════════════════════════════════════════════════════════════

async function incrementStat(statName) {
  try {
    const storage = await chrome.storage.local.get(['extensionStats']);
    const stats = storage.extensionStats || {
      urlsCaptured: 0,
      urlsSent: 0,
      urlsBlocked: 0
    };
    
    stats[statName] = (stats[statName] || 0) + 1;
    
    await chrome.storage.local.set({ extensionStats: stats });
  } catch (error) {
    // Silently fail - stats are not critical
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE HANDLER - Dashboard can request stats
// ═══════════════════════════════════════════════════════════════════════════

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getStats') {
    chrome.storage.local.get(['extensionStats'], (result) => {
      sendResponse(result.extensionStats || {
        urlsCaptured: 0,
        urlsSent: 0,
        urlsBlocked: 0
      });
    });
    return true; // Keep message channel open for async response
  }
  
  if (message.action === 'clearStats') {
    chrome.storage.local.set({
      extensionStats: {
        urlsCaptured: 0,
        urlsSent: 0,
        urlsBlocked: 0
      }
    }, () => {
      sendResponse({ success: true });
    });
    return true;
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PERIODIC CLEANUP
// ═══════════════════════════════════════════════════════════════════════════

// Clear old cooldown entries every minute
setInterval(() => {
  const now = Date.now();
  const cutoff = now - (SCAN_COOLDOWN * 2); // Clear entries older than 2x cooldown
  
  for (const [url, timestamp] of recentScans.entries()) {
    if (timestamp < cutoff) {
      recentScans.delete(url);
    }
  }
  
  if (recentScans.size > 1000) {
    // If map gets too large, clear oldest 50%
    const entries = Array.from(recentScans.entries());
    entries.sort((a, b) => a[1] - b[1]);
    const toDelete = entries.slice(0, Math.floor(entries.length / 2));
    for (const [url] of toDelete) {
      recentScans.delete(url);
    }
    console.log(`🧹 [CLEANUP] Cleared ${toDelete.length} old scan entries`);
  }
}, 60000);

console.log('✅ Extension background service initialized');
console.log('📡 Monitoring navigation events...');
console.log('🎯 Dashboard: ' + DASHBOARD_URL);
