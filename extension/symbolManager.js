// ============================================
// SYMBOL/ICON MANAGER - Real-time Symbol Updates
// ============================================

const SymbolManager = {
  // Symbol definitions for different threat levels
  symbols: {
    SAFE: {
      icon: '✓',
      emoji: '🟢',
      color: '#00ff88',
      bgColor: 'rgba(0, 255, 136, 0.1)',
      borderColor: 'rgba(0, 255, 136, 0.3)',
      badgeText: '✓',
      badgeColor: '#00ff88',
      title: 'SAFE',
      animationClass: 'symbol-safe'
    },
    SUSPICIOUS: {
      icon: '⚠',
      emoji: '🟡',
      color: '#ffc107',
      bgColor: 'rgba(255, 193, 7, 0.1)',
      borderColor: 'rgba(255, 193, 7, 0.3)',
      badgeText: '!',
      badgeColor: '#ffc107',
      title: 'SUSPICIOUS',
      animationClass: 'symbol-suspicious'
    },
    THREAT: {
      icon: '✗',
      emoji: '🔴',
      color: '#ff5252',
      bgColor: 'rgba(255, 82, 82, 0.1)',
      borderColor: 'rgba(255, 82, 82, 0.3)',
      badgeText: '✗',
      badgeColor: '#ff5252',
      title: 'THREAT',
      animationClass: 'symbol-threat'
    },
    SCANNING: {
      icon: '◉',
      emoji: '⚙️',
      color: '#2196f3',
      bgColor: 'rgba(33, 150, 243, 0.1)',
      borderColor: 'rgba(33, 150, 243, 0.3)',
      badgeText: '○',
      badgeColor: '#2196f3',
      title: 'SCANNING',
      animationClass: 'symbol-scanning'
    }
  },

  // Get symbol based on risk score
  getSymbolByRiskScore(riskScore) {
    if (riskScore >= 70) return 'THREAT';
    if (riskScore >= 40) return 'SUSPICIOUS';
    if (riskScore > 0 && riskScore < 40) return 'SAFE';
    return 'SAFE';
  },

  // Get symbol based on classification
  getSymbolByClassification(classification) {
    const classMap = {
      'MALICIOUS': 'THREAT',
      'SUSPICIOUS': 'SUSPICIOUS',
      'BENIGN': 'SAFE',
      'SAFE': 'SAFE'
    };
    return classMap[classification] || 'SAFE';
  },

  // Update extension badge icon
  async updateBadge(symbolKey, tabId = null) {
    const symbol = this.symbols[symbolKey];
    if (!symbol) return;

    try {
      // Update badge text
      await chrome.action.setBadgeText({ 
        text: symbol.badgeText,
        tabId: tabId
      });

      // Update badge color
      await chrome.action.setBadgeBackgroundColor({ 
        color: symbol.badgeColor,
        tabId: tabId
      });

      console.log(`🔄 Badge updated: ${symbolKey}`);
    } catch (error) {
      console.error('Error updating badge:', error);
    }
  },

  // Update status in popup or dashboard
  async updateStatusDisplay(symbolKey, elementSelector = '.stat-card-safe') {
    const symbol = this.symbols[symbolKey];
    if (!symbol) return;

    const element = document.querySelector(elementSelector);
    if (!element) return;

    try {
      element.style.transition = 'all 0.3s ease-in-out';
      element.style.background = symbol.bgColor;
      element.style.borderColor = symbol.borderColor;

      const statusValue = element.querySelector('[data-status-value]') || element;
      statusValue.style.color = symbol.color;
      statusValue.textContent = `${symbol.emoji} ${symbol.title}`;

      // Add pulse animation for threat levels
      if (symbolKey === 'THREAT' || symbolKey === 'SCANNING') {
        element.classList.add(symbol.animationClass);
      } else {
        element.classList.remove('symbol-threat', 'symbol-scanning');
      }

      console.log(`✅ Status display updated: ${symbolKey}`);
    } catch (error) {
      console.error('Error updating status display:', error);
    }
  },

  // Update icon in real-time during scanning
  async updateScanningState(isScanning, tabId = null) {
    if (isScanning) {
      await this.updateBadge('SCANNING', tabId);
    }
  },

  // Animate symbol change
  animateSymbolChange(oldSymbol, newSymbol) {
    const oldData = this.symbols[oldSymbol];
    const newData = this.symbols[newSymbol];

    if (!oldData || !newData) return;

    // Create animation effect
    const element = document.querySelector('[data-status-value]');
    if (element) {
      element.style.animation = 'symbolFlash 0.5s ease-in-out';
      setTimeout(() => {
        element.style.animation = '';
      }, 500);
    }
  },

  // Broadcast symbol update to all components
  async broadcastSymbolUpdate(symbolKey, tabId, additionalData = {}) {
    const message = {
      type: 'SYMBOL_UPDATE',
      symbol: symbolKey,
      symbolData: this.symbols[symbolKey],
      tabId: tabId,
      timestamp: new Date().toISOString(),
      ...additionalData
    };

    // Send to popup
    chrome.runtime.sendMessage(message).catch(() => {
      console.log('Popup not open for symbol update');
    });

    // Send to content script
    if (tabId) {
      chrome.tabs.sendMessage(tabId, message).catch(() => {
        console.log('Content script not available');
      });
    }
  },

  // Get symbol HTML representation
  getSymbolHTML(symbolKey, size = 'medium') {
    const symbol = this.symbols[symbolKey];
    if (!symbol) return '';

    const sizeClass = `symbol-${size}`;
    return `
      <div class="symbol ${sizeClass}" style="color: ${symbol.color}; border-color: ${symbol.borderColor};">
        <span class="symbol-icon">${symbol.emoji}</span>
        <span class="symbol-text">${symbol.title}</span>
      </div>
    `;
  },

  // Track symbol history for trend analysis
  symbolHistory: [],

  recordSymbolChange(symbolKey, riskScore, tabUrl) {
    this.symbolHistory.push({
      symbol: symbolKey,
      riskScore: riskScore,
      url: tabUrl,
      timestamp: new Date().toISOString()
    });

    // Keep only last 100 changes
    if (this.symbolHistory.length > 100) {
      this.symbolHistory.shift();
    }

    console.log(`📊 Symbol change recorded: ${symbolKey}`);
  },

  // Get symbol trend
  getSymbolTrend(tabUrl) {
    return this.symbolHistory.filter(entry => entry.url === tabUrl);
  }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SymbolManager;
}
