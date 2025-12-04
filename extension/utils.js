// ============================================================
// MALWARE SNIPPER - UTILITY FUNCTIONS
// ============================================================
// Helper functions for URL validation, risk calculation, formatting

// ============================================================
// URL VALIDATION
// ============================================================

/**
 * Check if a string is a valid URL
 */
function isValidURL(urlString) {
  try {
    new URL(urlString);
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Extract domain from URL
 */
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (error) {
    return null;
  }
}

/**
 * Check if URL is HTTP (non-HTTPS)
 */
function isHTTP(url) {
  try {
    return new URL(url).protocol === 'http:';
  } catch (error) {
    return false;
  }
}

/**
 * Check if URL uses an IP address instead of domain
 */
function isIPAddress(url) {
  try {
    const hostname = new URL(url).hostname;
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  } catch (error) {
    return false;
  }
}

// ============================================================
// RISK CALCULATION HELPERS
// ============================================================

/**
 * Check if domain uses a suspicious TLD
 */
function hasSuspiciousTLD(url) {
  try {
    const hostname = new URL(url).hostname;
    const suspiciousTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.gq',     // Free domain registrars
      '.top', '.trade', '.loan', '.click',   // Suspicious generic TLDs
      '.download', '.stream', '.webcam'      // Commonly abused
    ];
    return suspiciousTLDs.some(tld => hostname.endsWith(tld));
  } catch (error) {
    return false;
  }
}

/**
 * Check for excessive subdomains (suspicious pattern)
 */
function hasExcessiveSubdomains(url) {
  try {
    const hostname = new URL(url).hostname;
    const domainParts = hostname.split('.');
    return domainParts.length > 3; // More than subdomain.domain.tld
  } catch (error) {
    return false;
  }
}

/**
 * Check if URL is unusually long (suspicious pattern)
 */
function hasExcessiveLength(url) {
  return url.length > 100;
}

/**
 * Check for suspicious special characters
 */
function hasSuspiciousCharacters(url) {
  // @ character (URL spoofing)
  if (url.includes('@')) return true;
  
  // URL encoding (often used to obfuscate)
  if (url.includes('%')) return true;
  
  return false;
}

/**
 * Check if URL matches known malicious patterns
 */
function matchesMaliciousPattern(url) {
  const maliciousPatterns = [
    /phishing/i,
    /exploit/i,
    /malware/i,
    /ransomware/i,
    /trojan/i,
    /crypto.*miner/i,
    /bit.*coin.*mining/i
  ];
  
  return maliciousPatterns.some(pattern => pattern.test(url));
}

// ============================================================
// TIMESTAMP FORMATTING
// ============================================================

/**
 * Format timestamp to readable time string
 */
function formatTime(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

/**
 * Format timestamp to readable date and time
 */
function formatDateTime(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

/**
 * Get time ago string (e.g., "5 minutes ago")
 */
function getTimeAgo(timestamp) {
  const now = Date.now();
  const diff = now - timestamp;
  
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (seconds < 60) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  
  return formatDateTime(timestamp);
}

// ============================================================
// THREAT LEVEL HELPERS
// ============================================================

/**
 * Get color for risk score
 */
function getColorForRiskScore(riskScore) {
  if (riskScore >= 51) return '#F44336';  // Red - Malicious
  if (riskScore >= 21) return '#FF9800';  // Orange - Suspicious
  return '#4CAF50';                       // Green - Safe
}

/**
 * Get badge emoji for risk score
 */
function getBadgeForRiskScore(riskScore) {
  if (riskScore >= 51) return '🔴';  // Red circle
  if (riskScore >= 21) return '⚠️';  // Warning
  return '✅';                       // Checkmark
}

/**
 * Get classification text for risk score
 */
function getClassificationForRiskScore(riskScore) {
  if (riskScore >= 51) return 'MALICIOUS';
  if (riskScore >= 21) return 'SUSPICIOUS';
  return 'SAFE';
}

// ============================================================
// URL SANITIZATION
// ============================================================

/**
 * Sanitize URL for display (truncate and encode)
 */
function sanitizeURLForDisplay(url, maxLength = 60) {
  if (url.length <= maxLength) return url;
  
  const start = url.substring(0, maxLength - 3);
  return start + '...';
}

/**
 * Escape HTML special characters
 */
function escapeHTML(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================================
// LOCAL STORAGE HELPERS
// ============================================================

/**
 * Save data to Chrome storage
 */
async function saveToStorage(key, data) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set({ [key]: data }, () => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve();
      }
    });
  });
}

/**
 * Get data from Chrome storage
 */
async function getFromStorage(key) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get([key], (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(result[key]);
      }
    });
  });
}

/**
 * Clear Chrome storage
 */
async function clearStorage() {
  return new Promise((resolve, reject) => {
    chrome.storage.local.clear(() => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve();
      }
    });
  });
}

// ============================================================
// LOGGING UTILITIES
// ============================================================

/**
 * Log with category prefix
 */
function logWithCategory(category, message, data = null) {
  const timestamp = new Date().toLocaleTimeString();
  const prefix = `[${timestamp}] [${category}]`;
  
  if (data) {
    console.log(prefix, message, data);
  } else {
    console.log(prefix, message);
  }
}

/**
 * Log error with context
 */
function logError(category, error) {
  const timestamp = new Date().toLocaleTimeString();
  const prefix = `[${timestamp}] [${category}] ERROR`;
  console.error(prefix, error.message, error);
}

// ============================================================
// UUID GENERATION
// ============================================================

/**
 * Generate unique UUID for scan records
 */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

console.log('[UTILS] Utility functions loaded ✅');
