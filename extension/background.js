// ============================================
// MALWARESNIPPER - REAL-TIME EXTENSION
// Captures ACTUAL URL and JS content
// ============================================

console.log('🛡️ MalwareSnipper Extension Loaded');

const BACKEND_URL = 'http://localhost:5000';
const scanCache = new Map();
const CACHE_DURATION = 30000; // 30 seconds

// Stats tracking
let stats = {
  monitored: 0,
  threats: 0,
  status: 'SAFE'
};

// Initialize stats from storage
chrome.storage.local.get(['stats'], (result) => {
  if (result.stats) {
    stats = result.stats;
  }
});

// Save stats to storage
async function saveStats() {
  await chrome.storage.local.set({ stats });
  // Notify popup to update
  chrome.runtime.sendMessage({ action: 'statsUpdated' }).catch(() => {});
}

// Save scan to recent alerts
async function saveScanToAlerts(result) {
  const scanRecord = {
    url: result.url || result.pageData?.url,
    classification: result.classification,
    risk_score: result.risk_score,
    timestamp: result.timestamp || new Date().toISOString()
  };
  
  // Get existing scans
  const storage = await chrome.storage.local.get(['recentScans']);
  let recentScans = storage.recentScans || [];
  
  // Add new scan at the beginning
  recentScans.unshift(scanRecord);
  
  // Keep only last 50 scans
  recentScans = recentScans.slice(0, 50);
  
  // Save back to storage
  await chrome.storage.local.set({ recentScans });
  
  // Notify popup to update
  chrome.runtime.sendMessage({ action: 'statsUpdated' }).catch(() => {});
}

// ====================
// CAPTURE REAL PAGE DATA
// ====================
async function capturePageData(tabId, url) {
  try {
    // Execute script in the page to capture JS content
    const results = await chrome.scripting.executeScript({
      target: { tabId: tabId },
      function: extractPageData
    });

    const pageData = results[0].result;
    
    return {
      url: url,
      timestamp: Date.now(),
      page_title: pageData.title,
      scripts: pageData.scripts,
      inline_scripts: pageData.inlineScripts,
      external_resources: pageData.externalResources,
      dom_structure: pageData.domStructure,
      meta_tags: pageData.metaTags,
      forms: pageData.forms,
      iframes: pageData.iframes
    };
  } catch (error) {
    console.error('❌ Error capturing page data:', error);
    return {
      url: url,
      timestamp: Date.now(),
      page_title: 'Unable to capture',
      scripts: [],
      inline_scripts: [],
      external_resources: [],
      dom_structure: { total_elements: 0 },
      meta_tags: {},
      forms: 0,
      iframes: 0
    };
  }
}

// ====================
// EXTRACT FUNCTION (Runs in page context)
// ====================
function extractPageData() {
  const data = {
    title: document.title,
    scripts: [],
    inlineScripts: [],
    externalResources: [],
    domStructure: {
      total_elements: document.getElementsByTagName('*').length,
      total_scripts: document.scripts.length,
      total_links: document.links.length,
      total_images: document.images.length
    },
    metaTags: {},
    forms: document.forms.length,
    iframes: document.getElementsByTagName('iframe').length
  };

  // Capture external scripts
  document.querySelectorAll('script[src]').forEach(script => {
    data.scripts.push(script.src);
    data.externalResources.push(script.src);
  });

  // Capture inline scripts (first 500 chars each)
  document.querySelectorAll('script:not([src])').forEach(script => {
    const content = script.textContent.trim();
    if (content.length > 0) {
      data.inlineScripts.push(content.substring(0, 500));
    }
  });

  // Capture other external resources
  document.querySelectorAll('link[href], img[src]').forEach(elem => {
    const url = elem.href || elem.src;
    if (url && !data.externalResources.includes(url)) {
      data.externalResources.push(url);
    }
  });

  // Capture meta tags
  document.querySelectorAll('meta').forEach(meta => {
    const name = meta.getAttribute('name') || meta.getAttribute('property');
    const content = meta.getAttribute('content');
    if (name && content) {
      data.metaTags[name] = content;
    }
  });

  return data;
}

// ====================
// SEND TO BACKEND FOR REAL-TIME ANALYSIS
// ====================
async function scanURL(tabId, url) {
  // Check if recently scanned
  const cacheKey = url;
  if (scanCache.has(cacheKey)) {
    const cached = scanCache.get(cacheKey);
    if (Date.now() - cached.timestamp < CACHE_DURATION) {
      console.log('⏭️ Using cached result for:', url);
      return cached.result;
    }
  }

  console.log('🔍 Scanning:', url);
  
  try {
    // Show scanning notification
    await chrome.action.setBadgeText({ text: '...' });
    await chrome.action.setBadgeBackgroundColor({ color: '#FFA500' });

    // Capture REAL page data
    const pageData = await capturePageData(tabId, url);
    
    console.log('📤 Sending real data to backend:', {
      url: pageData.url,
      scripts: pageData.scripts.length,
      inlineScripts: pageData.inline_scripts.length,
      resources: pageData.external_resources.length
    });

    // Send to backend with timeout (non-blocking)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
    
    const fetchPromise = fetch(`${BACKEND_URL}/api/scan-realtime`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Extension-Version': '1.0.0'
      },
      body: JSON.stringify(pageData),
      signal: controller.signal
    });
    
    // Don't block extension - continue in background
    fetchPromise
      .then(async response => {
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`Backend error: ${response.status}`);
        }

        const result = await response.json();
        
        console.log('✅ Analysis complete:', result.final_classification || result.classification);

        // Update stats
        stats.monitored++;
        const classification = result.final_classification || result.classification || 'BENIGN';
        if (classification === 'MALICIOUS' || classification === 'SUSPICIOUS') {
          stats.threats++;
          stats.status = 'THREAT';
        }
        await saveStats();
        
        // Save to recent alerts
        await saveScanToAlerts({
          url: url,
          classification: classification,
          risk_score: result.overall_risk || result.risk_score || 0,
          timestamp: result.timestamp || new Date().toISOString()
        });

        // Cache result
        scanCache.set(cacheKey, {
          timestamp: Date.now(),
          result: result
        });

        // Update badge based on result
        const badge = {
          'BENIGN': { text: '✓', color: '#10B981' },
          'SUSPICIOUS': { text: '⚠', color: '#F59E0B' },
          'MALICIOUS': { text: '✗', color: '#EF4444' }
        }[classification] || { text: '?', color: '#6B7280' };

        await chrome.action.setBadgeText({ text: badge.text });
        await chrome.action.setBadgeBackgroundColor({ color: badge.color });

        // Show notification for threats
        if (classification === 'MALICIOUS') {
          await chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: '🚨 MALICIOUS SITE DETECTED',
            message: `${url}\nThreat Score: ${result.overall_risk || result.risk_score || 0}%`,
            priority: 2
          });
        } else if (classification === 'SUSPICIOUS') {
          await chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: '⚠️ Suspicious Activity',
            message: `${url}\nRisk Score: ${result.overall_risk || result.risk_score || 0}%`,
            priority: 1
          });
        }

        return result;
      })
      .catch(error => {
        clearTimeout(timeoutId);
        console.error('❌ Scan failed:', error);
        chrome.action.setBadgeText({ text: '✗' });
        chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });
      });
    
    // Return immediately - don't block navigation
    return { status: 'scanning', url: url };

  } catch (error) {
    console.error('❌ Scan failed:', error);
    await chrome.action.setBadgeText({ text: '✗' });
    await chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });
    return {
      error: error.message,
      classification: 'ERROR',
      risk_score: 0
    };
  }
}

// ====================
// VALIDATE URL
// ====================
function shouldScan(url) {
  if (!url) return false;
  
  // Skip system URLs
  if (url.startsWith('chrome://') || 
      url.startsWith('chrome-extension://') ||
      url.startsWith('edge://') ||
      url.startsWith('about:') ||
      url.startsWith('data:')) {
    return false;
  }
  
  // Skip localhost (don't scan dashboard)
  if (url.includes('localhost') || url.includes('127.0.0.1')) {
    return false;
  }
  
  // Only scan http/https
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    return false;
  }
  
  return true;
}

// ====================
// AUTO-SCAN ON NAVIGATION
// ====================
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only scan main frame
  if (details.frameId !== 0) return;
  
  const url = details.url;
  
  if (shouldScan(url)) {
    // Wait a bit for page to load
    setTimeout(() => {
      scanURL(details.tabId, url);
    }, 1000);
  } else {
    console.log('⏭️ Skipped:', url);
  }
});

// ====================
// MANUAL SCAN (Icon Click)
// ====================
chrome.action.onClicked.addListener(async (tab) => {
  if (shouldScan(tab.url)) {
    await scanURL(tab.id, tab.url);
  } else {
    await chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Cannot Scan',
      message: 'This URL cannot be scanned (system page or localhost)',
      priority: 0
    });
  }
});

// ====================
// MESSAGE HANDLER (Popup communication)
// ====================
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanCurrent') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs[0]) {
        const result = await scanURL(tabs[0].id, tabs[0].url);
        sendResponse(result);
      }
    });
    return true; // Keep channel open for async response
  }
  
  if (request.action === 'getStatus') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && scanCache.has(tabs[0].url)) {
        sendResponse(scanCache.get(tabs[0].url).result);
      } else {
        sendResponse({ status: 'not_scanned' });
      }
    });
    return true;
  }
});

// ====================
// CLEANUP OLD CACHE
// ====================
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of scanCache.entries()) {
    if (now - value.timestamp > CACHE_DURATION * 2) {
      scanCache.delete(key);
    }
  }
}, 60000); // Every minute

console.log('✅ MalwareSnipper Ready - Real-time scanning enabled');
