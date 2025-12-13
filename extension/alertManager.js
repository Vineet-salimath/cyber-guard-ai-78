// ============================================
// ALERT MANAGER - Real-time Alert Stream Updates
// ============================================

const AlertManager = {
  // In-memory alert queue for real-time updates
  alertQueue: [],
  maxAlerts: 50,
  updateInterval: 1000, // Update every 1 second
  listeners: [],

  // Alert structure template
  createAlert(data) {
    return {
      id: this.generateAlertId(),
      url: data.url,
      classification: data.classification,
      risk_score: data.risk_score || 0,
      timestamp: data.timestamp || new Date().toISOString(),
      details: data.details || {},
      isNew: true,
      viewed: false,
      severity: this.calculateSeverity(data.risk_score),
      threatType: this.getThreatType(data.classification)
    };
  },

  // Generate unique alert ID
  generateAlertId() {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  },

  // Calculate severity based on risk score
  calculateSeverity(riskScore) {
    if (riskScore >= 80) return 'CRITICAL';
    if (riskScore >= 60) return 'HIGH';
    if (riskScore >= 40) return 'MEDIUM';
    return 'LOW';
  },

  // Get threat type classification
  getThreatType(classification) {
    const typeMap = {
      'MALICIOUS': 'Malware',
      'SUSPICIOUS': 'Suspicious Activity',
      'PHISHING': 'Phishing Attempt',
      'BENIGN': 'Clean',
      'SAFE': 'Safe'
    };
    return typeMap[classification] || 'Unknown Threat';
  },

  // Add alert to queue and broadcast
  async addAlert(alertData) {
    const alert = this.createAlert(alertData);

    // Add to queue
    this.alertQueue.unshift(alert);

    // Keep only max alerts
    if (this.alertQueue.length > this.maxAlerts) {
      this.alertQueue.pop();
    }

    // Save to storage for persistence
    await this.saveAlertsToStorage();

    // Broadcast to all listeners
    await this.broadcastAlert(alert);

    console.log(`🚨 Alert added: ${alert.classification} - ${alert.url}`);

    return alert;
  },

  // Broadcast alert to all components
  async broadcastAlert(alert) {
    const message = {
      type: 'ALERT_UPDATE',
      alert: alert,
      timestamp: new Date().toISOString()
    };

    // Send to popup
    chrome.runtime.sendMessage(message).catch(() => {
      console.log('Popup not open for alert update');
    });

    // Trigger listeners
    this.listeners.forEach(callback => {
      try {
        callback(alert);
      } catch (error) {
        console.error('Error in alert listener:', error);
      }
    });

    // Persist alert
    await chrome.storage.local.get(['recentScans'], (result) => {
      const scans = result.recentScans || [];
      scans.unshift({
        url: alert.url,
        classification: alert.classification,
        risk_score: alert.risk_score,
        timestamp: alert.timestamp,
        severity: alert.severity,
        id: alert.id
      });

      // Keep only 100 recent scans
      const trimmedScans = scans.slice(0, 100);
      chrome.storage.local.set({ recentScans: trimmedScans });
    });
  },

  // Subscribe to alert updates
  onAlertUpdate(callback) {
    this.listeners.push(callback);
  },

  // Get all alerts
  getAlerts(limit = 10) {
    return this.alertQueue.slice(0, limit);
  },

  // Get alert by ID
  getAlertById(alertId) {
    return this.alertQueue.find(alert => alert.id === alertId);
  },

  // Filter alerts by severity
  getAlertsBySeverity(severity) {
    return this.alertQueue.filter(alert => alert.severity === severity);
  },

  // Filter alerts by threat type
  getAlertsByThreatType(threatType) {
    return this.alertQueue.filter(alert => alert.threatType === threatType);
  },

  // Get unread alerts count
  getUnreadCount() {
    return this.alertQueue.filter(alert => alert.isNew).length;
  },

  // Mark alert as read
  markAsRead(alertId) {
    const alert = this.getAlertById(alertId);
    if (alert) {
      alert.isNew = false;
    }
  },

  // Mark all as read
  markAllAsRead() {
    this.alertQueue.forEach(alert => {
      alert.isNew = false;
    });
  },

  // Dismiss alert
  dismissAlert(alertId) {
    const index = this.alertQueue.findIndex(alert => alert.id === alertId);
    if (index > -1) {
      this.alertQueue.splice(index, 1);
    }
  },

  // Save alerts to storage
  async saveAlertsToStorage() {
    return new Promise((resolve) => {
      const alertsData = this.alertQueue.map(alert => ({
        id: alert.id,
        url: alert.url,
        classification: alert.classification,
        risk_score: alert.risk_score,
        timestamp: alert.timestamp,
        severity: alert.severity,
        threatType: alert.threatType,
        viewed: alert.viewed
      }));

      chrome.storage.local.set({
        alertQueue: alertsData,
        alertStats: {
          total: this.alertQueue.length,
          unread: this.getUnreadCount(),
          critical: this.getAlertsBySeverity('CRITICAL').length,
          high: this.getAlertsBySeverity('HIGH').length
        }
      }, resolve);
    });
  },

  // Load alerts from storage
  async loadAlertsFromStorage() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['alertQueue'], (result) => {
        if (result.alertQueue) {
          this.alertQueue = result.alertQueue;
          console.log(`📥 Loaded ${this.alertQueue.length} alerts from storage`);
        }
        resolve(this.alertQueue);
      });
    });
  },

  // Get alert statistics
  getAlertStats() {
    return {
      total: this.alertQueue.length,
      unread: this.getUnreadCount(),
      critical: this.getAlertsBySeverity('CRITICAL').length,
      high: this.getAlertsBySeverity('HIGH').length,
      medium: this.getAlertsBySeverity('MEDIUM').length,
      low: this.getAlertsBySeverity('LOW').length,
      malware: this.getAlertsByThreatType('Malware').length,
      phishing: this.getAlertsByThreatType('Phishing Attempt').length,
      suspicious: this.getAlertsByThreatType('Suspicious Activity').length
    };
  },

  // Start continuous alert stream (checks for updates)
  startAlertStream(updateCallback, interval = 1000) {
    console.log('📡 Starting alert stream...');

    const streamInterval = setInterval(async () => {
      // Trigger update callback with current alerts
      if (updateCallback && typeof updateCallback === 'function') {
        updateCallback({
          alerts: this.getAlerts(),
          stats: this.getAlertStats(),
          timestamp: new Date().toISOString()
        });
      }
    }, interval);

    // Return function to stop stream
    return () => {
      clearInterval(streamInterval);
      console.log('📴 Alert stream stopped');
    };
  },

  // Generate alert HTML
  generateAlertHTML(alert, compact = false) {
    const severityColor = this.getSeverityColor(alert.severity);
    const riskColor = this.getRiskColor(alert.risk_score);

    if (compact) {
      return `
        <div class="alert-item compact" data-alert-id="${alert.id}">
          <span class="alert-severity" style="background: ${severityColor};">${alert.severity}</span>
          <span class="alert-url">${this.truncateUrl(alert.url, 50)}</span>
          <span class="alert-risk" style="color: ${riskColor};">${alert.risk_score}%</span>
          <span class="alert-time">${this.formatTime(alert.timestamp)}</span>
        </div>
      `;
    }

    return `
      <div class="alert-item full" data-alert-id="${alert.id}">
        <div class="alert-header">
          <span class="alert-severity ${alert.severity.toLowerCase()}" style="background: ${severityColor};">
            ${alert.severity}
          </span>
          <span class="alert-threat-type">${alert.threatType}</span>
          <span class="alert-risk" style="color: ${riskColor};">Risk: ${alert.risk_score}%</span>
          <span class="alert-badge ${alert.isNew ? 'new' : ''}">${alert.isNew ? 'NEW' : ''}</span>
        </div>
        <div class="alert-url" title="${alert.url}">${alert.url}</div>
        <div class="alert-footer">
          <span class="alert-time">${this.formatTime(alert.timestamp)}</span>
          <button class="btn-dismiss" data-alert-id="${alert.id}">Dismiss</button>
          <button class="btn-details" data-alert-id="${alert.id}">View Details</button>
        </div>
      </div>
    `;
  },

  // Helper: Get severity color
  getSeverityColor(severity) {
    const colors = {
      'CRITICAL': '#ff1744',
      'HIGH': '#ff5252',
      'MEDIUM': '#ffc107',
      'LOW': '#ffb74d'
    };
    return colors[severity] || '#9e9e9e';
  },

  // Helper: Get risk color
  getRiskColor(riskScore) {
    if (riskScore >= 70) return '#ff1744';
    if (riskScore >= 40) return '#ffc107';
    return '#4caf50';
  },

  // Helper: Truncate URL
  truncateUrl(url, maxLength = 50) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  },

  // Helper: Format timestamp
  formatTime(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    const diff = now - time;

    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return 'Just now';
  },

  // Clear all alerts
  clearAllAlerts() {
    this.alertQueue = [];
    chrome.storage.local.set({ alertQueue: [], alertStats: {} });
    console.log('🗑️ All alerts cleared');
  }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AlertManager;
}
