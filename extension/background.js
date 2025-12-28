// ============================================
// MALWARESNIPPER - REAL-TIME EXTENSION
// Captures ACTUAL URL and JS content
// ============================================

console.log('🛡️ MalwareSnipper Extension Loaded');

const BACKEND_URL = 'http://localhost:5000';
const scanCache = new Map();
const CACHE_DURATION = 30000; // 30 seconds
const scansInProgress = new Map(); // Track ongoing scans

// ============================================
// SIMPLE SCANNING - ONE SCAN PER URL
// ============================================

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    // Only intercept main frame navigation (pages, not resources)
    if (details.type === 'main_frame' && scanningEnabled) {
      const url = details.url;
      const tabId = details.tabId;
      
      // Skip system URLs and extension URLs
      if (url.startsWith('chrome://') || 
          url.startsWith('chrome-extension://') ||
          url.startsWith('edge://') ||
          url.startsWith('about:') ||
          url.startsWith('data:')) {
        return;
      }

      // Don't re-scan if already in progress
      if (scansInProgress.has(url)) {
        console.log('⏳ Scan already in progress for:', url);
        return;
      }

      console.log('🔍 SCAN: URL intercepted:', url, 'TabID:', tabId);
      scansInProgress.set(url, { timestamp: Date.now(), tabId: tabId });

      try {
        // Send to backend for scanning
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);
        
        fetch(`${BACKEND_URL}/api/scan-realtime`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url }),
          signal: controller.signal
        })
          .then(async response => {
            clearTimeout(timeoutId);
            if (!response.ok) throw new Error(`Backend error: ${response.status}`);
            
            const result = await response.json();
            const riskScore = result.overall_risk || result.risk_score || 0;
            const classification = result.final_classification || result.classification || 'BENIGN';
            
            console.log('✅ Scan result:', classification, 'Risk Score:', riskScore);
            
            // Convert to notification status
            let notificationStatus = 'SAFE';
            if (classification === 'MALICIOUS' || classification === 'RANSOMWARE') {
              notificationStatus = 'MALICIOUS';
            } else if (classification === 'SUSPICIOUS' || classification === 'PHISHING') {
              notificationStatus = 'SUSPICIOUS';
            }
            
            // Notify content script using tabId
            console.log('📢 Sending notification to Tab:', tabId);
            notifyContentScript(tabId, {
              url: url,
              status: notificationStatus,
              riskScore: riskScore,
              threats: result.detected_threats || []
            });
            
            scansInProgress.delete(url);
          })
          .catch(error => {
            clearTimeout(timeoutId);
            console.error('❌ Scan failed:', error);
            scansInProgress.delete(url);
          });

      } catch (error) {
        console.error('❌ Error in scan:', error);
        scansInProgress.delete(url);
      }
    }
  },
  { urls: ['<all_urls>'] }
);

// Helper function to send data to backend
async function sendToBackend(endpoint, data) {
  try {
    const response = await fetch(`${BACKEND_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });

    if (!response.ok) {
      console.error(`⚠️ Backend error (${response.status}):`, await response.text());
    }

    return await response.json();
  } catch (error) {
    console.error(`❌ Failed to send data to ${endpoint}:`, error);
    throw error;
  }
}

// Helper function to notify content script about scan result
function notifyContentScript(tabId, scanResult) {
  try {
    console.log('🔔 notifyContentScript called with tabId:', tabId);
    chrome.tabs.sendMessage(tabId, {
      type: 'SCAN_COMPLETE',
      data: {
        url: scanResult.url,
        status: scanResult.status,
        riskScore: scanResult.riskScore,
        threats: scanResult.threats || []
      }
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.log('⚠️ Content script message error:', chrome.runtime.lastError);
      } else {
        console.log('✅ Content script received message, response:', response);
      }
    });
  } catch (error) {
    console.error('❌ Error notifying content script:', error);
  }
}

// ============================================
// SCANNING STATE & CONTROL
// ============================================
let scanningEnabled = true;
let scanningSchedule = null;
let settingsState = {
  autoScan: true,
  blockThreats: true,
  threatAlerts: true,
  weeklyReports: true,
  updateNotifications: false
};

// Load scanning settings from storage
chrome.storage.local.get(['settings'], (result) => {
  if (result.settings) {
    settingsState = result.settings;
    scanningEnabled = result.settings.autoScan !== false;
  }
});

// Function to start real-time scanning
function startScanning() {
  scanningEnabled = true;
  console.log('🟢 Scanning ENABLED - Real-time threat detection active');
  
  // Resume web request monitoring
  if (!scanningSchedule) {
    scanningSchedule = setInterval(() => {
      // Periodic scan check
      console.log('📍 Scan cycle running...');
    }, 5000);
  }
}

// Function to stop all scanning
function stopScanning() {
  scanningEnabled = false;
  console.log('🔴 Scanning DISABLED - All scans halted');
  
  // Clear any scheduled scans
  if (scanningSchedule) {
    clearInterval(scanningSchedule);
    scanningSchedule = null;
  }
  
  // Clear active scan cache
  scanCache.clear();
}

// ============================================
// INITIALIZE MANAGERS FOR REAL-TIME UPDATES
// ============================================
// These will be loaded from their respective files
let SymbolManager = null;
let AlertManager = null;

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

// ============================================
// PHASE SCANNING IMPLEMENTATIONS
// These are integrated from scanner.js logic
// ============================================

// PHASE 1: INSTANT CHECKS (< 1 second)
async function performInstantChecks(url) {
  const results = {
    timestamp: Date.now(),
    url: url,
    phase: 'instant',
    checks: {}
  };

  try {
    // URL pattern analysis
    results.checks.urlAnalysis = analyzeURLPattern(url);
    
    // Local cache lookup
    results.checks.cachedResult = await checkLocalCache(url);
    
    // SSL/TLS check
    results.checks.sslStatus = await checkSSL(url);
    
    console.log('✅ PHASE 1 INSTANT checks complete:', results);
  } catch (error) {
    console.error('❌ Instant checks error:', error);
  }

  return results;
}

// PHASE 2: FAST SCAN (1-3 seconds)
async function performFastScan(url) {
  const results = {
    phase: 'fast',
    timestamp: Date.now(),
    url: url,
    checks: {}
  };

  try {
    // Run API calls in parallel
    const [vtResult] = await Promise.all([
      checkVirusTotal(url)
    ]);

    results.checks = { virustotal: vtResult };
    console.log('✅ PHASE 2 FAST scan complete:', results);
  } catch (error) {
    console.error('❌ Fast scan error:', error);
  }

  return results;
}

// PHASE 3: DEEP SCAN (3-15 seconds)
async function performDeepScan(url) {
  const results = {
    phase: 'deep',
    timestamp: Date.now(),
    url: url,
    checks: {}
  };

  try {
    // Heavy analysis
    results.checks.mlPrediction = await runMLModel(url);
    results.checks.scriptAnalysis = await analyzePageScripts(url);
    
    console.log('✅ PHASE 3 DEEP scan complete:', results);
  } catch (error) {
    console.error('❌ Deep scan error:', error);
  }

  return results;
}

// Helper: URL Pattern Analysis
function analyzeURLPattern(url) {
  let suspicionScore = 0;
  const indicators = [];

  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const path = urlObj.pathname;

    // Check suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.bit'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
      suspicionScore += 15;
      indicators.push('Suspicious TLD');
    }

    // Check URL length
    if (url.length > 75) {
      suspicionScore += 10;
      indicators.push('Long URL');
    }

    // Check IP address
    if (/^\d+\.\d+\.\d+\.\d+/.test(domain)) {
      suspicionScore += 20;
      indicators.push('IP-based URL');
    }

    // Check non-HTTPS
    if (!url.startsWith('https://') && !url.startsWith('http://localhost')) {
      suspicionScore += 5;
      indicators.push('Not HTTPS');
    }
  } catch (error) {
    console.error('URL pattern analysis error:', error);
  }

  return {
    score: Math.min(suspicionScore, 100),
    indicators: indicators,
    safeURL: suspicionScore < 30
  };
}

// Helper: Local cache lookup
async function checkLocalCache(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['scanCache'], (result) => {
      if (result.scanCache && result.scanCache[url]) {
        const cached = result.scanCache[url];
        const age = Date.now() - cached.timestamp;
        
        if (age < 24 * 60 * 60 * 1000) { // 24 hour TTL
          resolve({
            cached: true,
            result: cached,
            age: Math.floor(age / 1000)
          });
          return;
        }
      }
      resolve({ cached: false });
    });
  });
}

// Helper: SSL check
async function checkSSL(url) {
  try {
    if (!url.startsWith('https://')) {
      return { secure: false, reason: 'Not HTTPS' };
    }
    return { secure: true, certificateValid: true };
  } catch (error) {
    return { secure: false, reason: 'SSL check failed' };
  }
}

// Helper: VirusTotal check (calls existing backend)
async function checkVirusTotal(url) {
  try {
    const response = await fetch(`${BACKEND_URL}/api/scan-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();
    return {
      successful: true,
      malicious: data.stats?.malicious || 0,
      suspicious: data.stats?.suspicious || 0,
      harmless: data.stats?.harmless || 0,
      undetected: data.stats?.undetected || 0,
      riskScore: data.overall_risk_score || 0
    };
  } catch (error) {
    console.error('VirusTotal check error:', error);
    return { successful: false, error: error.message };
  }
}

// Helper: ML Model check
async function runMLModel(url) {
  try {
    const response = await fetch(`${BACKEND_URL}/api/threat-analysis`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, type: 'ml_analysis' })
    });

    const data = await response.json();
    return {
      successful: true,
      prediction: data.prediction || 'BENIGN',
      confidence: data.confidence || 0.5
    };
  } catch (error) {
    return { successful: false, error: error.message };
  }
}

// Helper: Page script analysis
async function analyzePageScripts(url) {
  try {
    const response = await fetch(url);
    const html = await response.text();
    
    const scripts = (html.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || []).length;
    const externalScripts = (html.match(/<script[^>]+src=['"]([^'"]+)['"]/gi) || []).length;

    return {
      successful: true,
      scriptCount: scripts,
      externalScripts: externalScripts
    };
  } catch (error) {
    return { successful: false, error: error.message };
  }
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
  // Check if scanning is enabled
  if (!scanningEnabled) {
    console.log('⛔ Scanning disabled - skipping URL:', url);
    return { error: 'Scanning is disabled in settings', status: 'disabled' };
  }

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

        // Extract risk score from backend response
        const riskScore = result.overall_risk || result.risk_score || 0;
        const classification = result.final_classification || result.classification || 'BENIGN';
        
        // Convert classification to notification status
        let notificationStatus = 'SAFE';
        if (classification === 'MALICIOUS' || classification === 'RANSOMWARE') {
          notificationStatus = 'MALICIOUS';
        } else if (classification === 'SUSPICIOUS' || classification === 'PHISHING' || classification === 'OBFUSCATED_JS') {
          notificationStatus = 'SUSPICIOUS';
        } else if (classification === 'THREAT') {
          notificationStatus = 'THREAT';
        }
        
        // Notify content script of scan result
        notifyContentScript(tabId, {
          url: url,
          status: notificationStatus,
          risk_score: riskScore,
          detected_threats: result.detected_threats || []
        });
        
        // Update stats
        stats.monitored++;
        if (classification === 'MALICIOUS' || classification === 'SUSPICIOUS') {
          stats.threats++;
          stats.status = 'THREAT';
        } else {
          stats.status = 'SAFE';
        }
        await saveStats();
        
        // ============================================
        // REAL-TIME SYMBOL UPDATE
        // ============================================
        if (SymbolManager) {
          // Determine symbol based on analysis
          const symbolKey = SymbolManager.getSymbolByRiskScore(riskScore);
          
          // Update badge immediately
          await SymbolManager.updateBadge(symbolKey, tabId);
          
          // Record symbol change for trend analysis
          SymbolManager.recordSymbolChange(symbolKey, riskScore, url);
          
          // Broadcast symbol update to popup
          await SymbolManager.broadcastSymbolUpdate(symbolKey, tabId, {
            riskScore: riskScore,
            classification: classification,
            url: url
          });
          
          console.log(`🔄 Symbol updated to: ${symbolKey}`);
        }
        
        // ✅ Scan complete and notified
        console.log('✅ Scan completed and notified to content script');
        
        // 🔥 Send real-time scan result to popup
        chrome.runtime.sendMessage({
          type: 'SCAN_RESULT',
          riskScore: riskScore,
          classification: classification,
          url: url,
          timestamp: new Date().toISOString()
        }).catch(err => console.log('Popup not open:', err));
        
        // Save to recent alerts
        await saveScanToAlerts({
          url: url,
          classification: classification,
          risk_score: riskScore,
          timestamp: result.timestamp || new Date().toISOString()
        });

        // Cache result
        scanCache.set(cacheKey, {
          timestamp: Date.now(),
          result: result
        });

        // Update badge based on result (legacy support)
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
  // Scanning control messages
  if (request.type === 'ENABLE_SCANNING') {
    settingsState.autoScan = true;
    chrome.storage.local.set({ settings: settingsState });
    startScanning();
    sendResponse({ status: 'scanning_enabled', message: 'Real-time scanning activated' });
    return true;
  }
  
  if (request.type === 'DISABLE_SCANNING') {
    settingsState.autoScan = false;
    chrome.storage.local.set({ settings: settingsState });
    stopScanning();
    sendResponse({ status: 'scanning_disabled', message: 'All scans halted' });
    return true;
  }

  if (request.type === 'UPDATE_THREAT_BLOCKING') {
    settingsState.blockThreats = request.payload.blockThreats;
    chrome.storage.local.set({ settings: settingsState });
    sendResponse({ status: 'updated', setting: 'blockThreats', value: request.payload.blockThreats });
    return true;
  }

  if (request.type === 'UPDATE_THREAT_ALERTS') {
    settingsState.threatAlerts = request.payload.threatAlerts;
    chrome.storage.local.set({ settings: settingsState });
    sendResponse({ status: 'updated', setting: 'threatAlerts', value: request.payload.threatAlerts });
    return true;
  }

  if (request.type === 'GET_SCANNING_STATUS') {
    sendResponse({ 
      scanningEnabled, 
      settings: settingsState,
      status: scanningEnabled ? 'active' : 'disabled'
    });
    return true;
  }

  // Legacy action messages
  if (request.action === 'scanCurrent') {
    if (!scanningEnabled) {
      sendResponse({ error: 'Scanning is disabled in settings' });
      return true;
    }
    
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

// ============================================
// INITIALIZE REAL-TIME MANAGERS
// ============================================
// These scripts are injected by the manifest
// They will be available as global objects once loaded

// Function to initialize managers when they're loaded
function initializeManagers() {
  if (typeof SymbolManager !== 'undefined' && SymbolManager !== null) {
    console.log('✅ SymbolManager initialized');
  }
  // AlertManager initialization removed - not needed for basic popup functionality
  console.log('✅ Managers initialization complete');
}

// Attempt to initialize managers
setTimeout(initializeManagers, 1000);

console.log('✅ MalwareSnipper Ready - Real-time scanning enabled with Symbol & Alert Managers');
