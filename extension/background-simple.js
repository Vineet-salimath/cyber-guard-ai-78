// ═══════════════════════════════════════════════════════════════════════════
// MALWARE SNIPPER - SIMPLE WORKING VERSION
// Extension → Backend → Dashboard (CLEAN & SIMPLE)
// ═══════════════════════════════════════════════════════════════════════════

const BACKEND_URL = 'http://localhost:5000';

// URLs to block
const BLOCKED_PATTERNS = [
  /^chrome:/,
  /^chrome-extension:/,
  /^about:/,
  /^file:/,
  /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|ttf)$/,
  /favicon\.ico/,
];

// Prevent duplicate scans
const recentScans = new Map();
const COOLDOWN = 5000; // 5 seconds

// ═══════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

chrome.runtime.onInstalled.addListener(() => {
  console.log('🛡️ MalwareSnipper Extension Installed');
  console.log('📡 Backend:', BACKEND_URL);
});

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATE URL
// ═══════════════════════════════════════════════════════════════════════════

function shouldScan(url) {
  if (!url || !url.startsWith('http')) return false;
  
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(url)) return false;
  }
  
  const lastScan = recentScans.get(url);
  if (lastScan && (Date.now() - lastScan) < COOLDOWN) {
    return false;
  }
  
  return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// SEND TO BACKEND
// ═══════════════════════════════════════════════════════════════════════════

async function sendToBackend(url) {
  recentScans.set(url, Date.now());
  
  console.log('📤 Sending:', url);
  
  try {
    const response = await fetch(`${BACKEND_URL}/api/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url: url,
        timestamp: Date.now(),
        source: 'extension'
      })
    });
    
    if (response.ok) {
      const result = await response.json();
      console.log('✅ Success:', result.risk);
    } else {
      console.error('❌ Failed:', response.status);
    }
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CAPTURE NAVIGATION
// ═══════════════════════════════════════════════════════════════════════════

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  
  const url = details.url;
  
  if (shouldScan(url)) {
    console.log('🌐 Visited:', url);
    sendToBackend(url);
  }
});

console.log('✅ Extension Ready');
