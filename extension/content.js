// MALWARE SNIPPER - CONTENT SCRIPT
// Injected into pages to show threat warnings and visual indicators

let threatWarningOverlay = null;
let currentThreatData = null;

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showThreatWarning') {
    currentThreatData = request.result;
    showThreatWarning(request.result);
    sendResponse({ displayed: true });
  }
  
  if (request.action === 'removeThreatWarning') {
    removeThreatWarning();
    sendResponse({ removed: true });
  }
  
  return true;
});

// Show threat warning overlay
function showThreatWarning(result) {
  // Remove existing overlay if present
  removeThreatWarning();
  
  const threatLevel = result.threat_level;
  const riskScore = result.overall_risk_score;
  
  // Create overlay
  threatWarningOverlay = document.createElement('div');
  threatWarningOverlay.id = 'malware-snipper-warning';
  
  // Styling based on threat level
  const styles = {
    'SUSPICIOUS': {
      background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
      icon: '⚠️',
      title: 'SUSPICIOUS WEBSITE DETECTED',
      borderColor: '#f59e0b'
    },
    'MALICIOUS': {
      background: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
      icon: '🚨',
      title: 'MALICIOUS WEBSITE DETECTED',
      borderColor: '#ef4444'
    }
  };
  
  const config = styles[threatLevel] || styles['SUSPICIOUS'];
  
  threatWarningOverlay.innerHTML = `
    <style>
      #malware-snipper-warning {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        z-index: 999999;
        background: ${config.background};
        color: white;
        padding: 16px 24px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        animation: slideDown 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
        border-bottom: 4px solid ${config.borderColor};
      }
      
      @keyframes slideDown {
        from {
          transform: translateY(-100%);
          opacity: 0;
        }
        to {
          transform: translateY(0);
          opacity: 1;
        }
      }
      
      #malware-snipper-warning .warning-container {
        max-width: 1200px;
        margin: 0 auto;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
      }
      
      #malware-snipper-warning .warning-content {
        display: flex;
        align-items: center;
        gap: 16px;
        flex: 1;
      }
      
      #malware-snipper-warning .warning-icon {
        font-size: 32px;
        animation: pulse 2s infinite;
      }
      
      @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.1); }
      }
      
      #malware-snipper-warning .warning-text h3 {
        margin: 0;
        font-size: 18px;
        font-weight: 700;
        letter-spacing: 0.5px;
      }
      
      #malware-snipper-warning .warning-text p {
        margin: 4px 0 0 0;
        font-size: 14px;
        opacity: 0.95;
      }
      
      #malware-snipper-warning .risk-badge {
        background: rgba(255, 255, 255, 0.25);
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 14px;
        backdrop-filter: blur(10px);
      }
      
      #malware-snipper-warning .warning-actions {
        display: flex;
        gap: 12px;
        align-items: center;
      }
      
      #malware-snipper-warning button {
        background: rgba(255, 255, 255, 0.2);
        border: 2px solid rgba(255, 255, 255, 0.4);
        color: white;
        padding: 10px 20px;
        border-radius: 8px;
        cursor: pointer;
        font-weight: 600;
        font-size: 14px;
        transition: all 0.2s;
        backdrop-filter: blur(10px);
      }
      
      #malware-snipper-warning button:hover {
        background: rgba(255, 255, 255, 0.3);
        border-color: rgba(255, 255, 255, 0.6);
        transform: translateY(-1px);
      }
      
      #malware-snipper-warning .close-btn {
        background: transparent;
        border: none;
        font-size: 24px;
        cursor: pointer;
        padding: 4px;
        opacity: 0.8;
        transition: opacity 0.2s;
      }
      
      #malware-snipper-warning .close-btn:hover {
        opacity: 1;
        transform: none;
      }
      
      #malware-snipper-warning .threat-details {
        font-size: 12px;
        opacity: 0.9;
        margin-top: 2px;
      }
    </style>
    
    <div class="warning-container">
      <div class="warning-content">
        <div class="warning-icon">${config.icon}</div>
        <div class="warning-text">
          <h3>${config.title}</h3>
          <p>This website has been flagged by ${result.stats.malicious + result.stats.suspicious} security engine(s)</p>
          <div class="threat-details">
            ${result.threat_names && result.threat_names.length > 0 
              ? `Threats: ${result.threat_names.slice(0, 3).join(', ')}${result.threat_names.length > 3 ? '...' : ''}`
              : 'Avoid entering personal or financial information'}
          </div>
        </div>
      </div>
      
      <div class="warning-actions">
        <div class="risk-badge">
          Risk: ${riskScore.toFixed(1)}%
        </div>
        <button id="ms-view-details">View Details</button>
        <button class="close-btn" id="ms-close-warning">✕</button>
      </div>
    </div>
  `;
  
  document.body.appendChild(threatWarningOverlay);
  
  // Add event listeners
  document.getElementById('ms-close-warning').addEventListener('click', () => {
    removeThreatWarning();
  });
  
  document.getElementById('ms-view-details').addEventListener('click', () => {
    openDashboard();
  });
  
  // Add red border to page
  document.body.style.border = `5px solid ${config.borderColor}`;
  document.body.style.boxSizing = 'border-box';
  
  console.log('🚨 Malware Snipper: Threat warning displayed');
}

// Remove threat warning overlay
function removeThreatWarning() {
  if (threatWarningOverlay) {
    threatWarningOverlay.remove();
    threatWarningOverlay = null;
  }
  document.body.style.border = '';
  document.body.style.boxSizing = '';
}

// Open dashboard with current URL
function openDashboard() {
  const currentUrl = window.location.href;
  const encodedUrl = encodeURIComponent(currentUrl);
  const dashboardUrl = `http://localhost:8081/dashboard?url=${encodedUrl}`;
  window.open(dashboardUrl, '_blank');
}

// Auto-show warning on page load if threat detected
chrome.runtime.sendMessage({ action: 'getCurrentScan' }, (response) => {
  if (response && response.result && response.result.threat_level !== 'SAFE') {
    showThreatWarning(response.result);
  }
});

console.log('🛡️ Malware Snipper Content Script Active');
