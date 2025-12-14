/**
 * Security System Initialization
 * Initializes all security services and sets up real-time monitoring
 */

import { securityConfigManager } from './SecurityConfigurationManager';
import { getThreatDetectionEngine } from './ThreatDetectionEngine';
import { getNotificationService } from './NotificationService';

/**
 * Initialize the entire security system
 */
export function initializeSecuritySystem() {
  console.log('[SecuritySystem] Initializing security system...');
  
  // Get service instances
  const configManager = securityConfigManager;
  const threatEngine = getThreatDetectionEngine();
  const notificationService = getNotificationService();
  
  // Setup threat detection event handlers
  threatEngine.onThreatDetected((threatData) => {
    console.log('[SecuritySystem] Threat detected, sending notification');
    notificationService.showThreatAlert(threatData);
  });
  
  threatEngine.onBlockingRequired((url, threatData) => {
    console.log('[SecuritySystem] Blocking required for:', url);
    notificationService.showBlockingAlert(url, threatData.type);
  });
  
  // Setup configuration change monitoring
  configManager.subscribe((change) => {
    console.log(`[SecuritySystem] Configuration changed: ${change.setting} = ${change.newValue}`);
    
    // Log all changes
    logSecurityEvent({
      type: 'CONFIG_CHANGE',
      setting: change.setting,
      oldValue: change.oldValue,
      newValue: change.newValue,
      timestamp: change.timestamp
    });
  });
  
  // Setup automatic scanning on page load and navigation
  setupAutomaticScanning(threatEngine);
  
  // Setup background scanning for extension
  setupExtensionScanning(threatEngine);
  
  console.log('[SecuritySystem] Security system initialized successfully');
  
  return {
    configManager,
    threatEngine,
    notificationService
  };
}

/**
 * Setup automatic scanning for page navigation
 */
function setupAutomaticScanning(threatEngine: any) {
  // Scan current page
  const currentUrl = window.location.href;
  console.log('[SecuritySystem] Scanning current page:', currentUrl);
  threatEngine.scanURL(currentUrl, {
    trigger: 'page-load',
    timestamp: Date.now()
  }).catch((error: any) => {
    console.error('[SecuritySystem] Initial scan failed:', error);
  });
  
  // Listen for navigation changes
  window.addEventListener('beforeunload', () => {
    const nextUrl = window.location.href;
    console.log('[SecuritySystem] Page navigation detected:', nextUrl);
    threatEngine.scanURL(nextUrl, {
      trigger: 'navigation',
      timestamp: Date.now()
    }).catch((error: any) => {
      console.error('[SecuritySystem] Navigation scan failed:', error);
    });
  });
  
  // Monitor for dynamic navigation (SPA)
  let lastUrl = window.location.href;
  setInterval(() => {
    if (window.location.href !== lastUrl) {
      lastUrl = window.location.href;
      console.log('[SecuritySystem] URL changed detected:', lastUrl);
      threatEngine.scanURL(lastUrl, {
        trigger: 'url-change',
        timestamp: Date.now()
      }).catch((error: any) => {
        console.error('[SecuritySystem] URL change scan failed:', error);
      });
    }
  }, 1000);
}

/**
 * Setup scanning integration with browser extension
 */
function setupExtensionScanning(threatEngine: any) {
  // Listen for messages from extension
  if (typeof window !== 'undefined' && (window as any).chrome?.runtime) {
    (window as any).chrome.runtime.onMessage.addListener(
      (request: any, sender: any, sendResponse: any) => {
        if (request.action === 'scanURL') {
          console.log('[SecuritySystem] Extension requested URL scan:', request.url);
          
          threatEngine.scanURL(request.url, {
            trigger: 'extension',
            sourceTab: sender.tab?.id,
            timestamp: Date.now()
          }).then((result: any) => {
            sendResponse({
              success: true,
              result: result
            });
          }).catch((error: any) => {
            sendResponse({
              success: false,
              error: error.message
            });
          });
        }
      }
    );
  }
}

/**
 * Log security events for audit trail
 */
function logSecurityEvent(event: Record<string, any>) {
  try {
    // Send to backend for logging
    fetch('/api/security/events', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        ...event,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href
      })
    }).catch(error => {
      console.error('[SecuritySystem] Failed to log event:', error);
    });
  } catch (error) {
    console.error('[SecuritySystem] Event logging failed:', error);
  }
}

/**
 * Get security system status
 */
export function getSecuritySystemStatus() {
  const configManager = securityConfigManager;
  const threatEngine = getThreatDetectionEngine();
  
  return {
    isInitialized: true,
    settings: configManager.getAllSettings(),
    activeScanCount: threatEngine.getActiveScanCount(),
    scanLogs: threatEngine.getScanLogs()
  };
}

export default initializeSecuritySystem;
