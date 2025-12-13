// ============================================
// REALTIME WEBSOCKET HANDLER
// Continuous server-to-client updates
// ============================================

class RealtimeWebSocketHandler {
  constructor(backendUrl = 'http://localhost:5000', wsPort = 8080) {
    this.backendUrl = backendUrl;
    this.wsUrl = `ws://localhost:${wsPort}`;
    this.ws = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 3000; // 3 seconds
    this.messageHandlers = {};
    this.listeners = [];
    
    console.log('🔌 WebSocket Handler initialized');
  }

  // Connect to WebSocket server
  connect() {
    try {
      console.log(`🔄 Attempting to connect to ${this.wsUrl}...`);
      
      this.ws = new WebSocket(this.wsUrl);

      this.ws.onopen = () => {
        console.log('✅ WebSocket connected');
        this.isConnected = true;
        this.reconnectAttempts = 0;
        
        // Send initial handshake
        this.send({
          type: 'HANDSHAKE',
          clientType: 'CHROME_EXTENSION',
          version: '1.0.0',
          timestamp: new Date().toISOString()
        });

        // Notify all listeners
        this.notifyListeners({
          type: 'CONNECTION',
          status: 'connected'
        });
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          console.log('📥 WebSocket message:', message.type);
          
          // Broadcast to all listeners
          this.notifyListeners(message);
          
          // Call specific handler if exists
          if (this.messageHandlers[message.type]) {
            this.messageHandlers[message.type](message);
          }
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };

      this.ws.onerror = (error) => {
        console.error('❌ WebSocket error:', error);
      };

      this.ws.onclose = () => {
        console.log('⚠️ WebSocket disconnected');
        this.isConnected = false;
        this.attemptReconnect();
      };
    } catch (error) {
      console.error('Error initializing WebSocket:', error);
      this.attemptReconnect();
    }
  }

  // Attempt to reconnect
  attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`🔄 Reconnecting in ${this.reconnectDelay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      
      setTimeout(() => this.connect(), this.reconnectDelay);
    } else {
      console.error('❌ Max reconnection attempts reached');
      
      // Notify listeners of connection failure
      this.notifyListeners({
        type: 'CONNECTION',
        status: 'failed'
      });
    }
  }

  // Send message to server
  send(message) {
    if (this.isConnected && this.ws) {
      try {
        this.ws.send(JSON.stringify(message));
        console.log('📤 Message sent:', message.type);
      } catch (error) {
        console.error('Error sending WebSocket message:', error);
      }
    } else {
      console.warn('WebSocket not connected, message queued:', message.type);
    }
  }

  // Register message handler
  on(messageType, callback) {
    this.messageHandlers[messageType] = callback;
  }

  // Subscribe to all messages
  subscribe(callback) {
    this.listeners.push(callback);
  }

  // Notify all subscribers
  notifyListeners(message) {
    this.listeners.forEach(callback => {
      try {
        callback(message);
      } catch (error) {
        console.error('Error in listener callback:', error);
      }
    });
  }

  // Send real-time scan update
  sendScanUpdate(scanData) {
    this.send({
      type: 'SCAN_UPDATE',
      data: scanData,
      timestamp: new Date().toISOString()
    });
  }

  // Send alert update
  sendAlertUpdate(alertData) {
    this.send({
      type: 'ALERT',
      data: alertData,
      timestamp: new Date().toISOString()
    });
  }

  // Request symbol update
  requestSymbolUpdate(tabUrl, riskScore) {
    this.send({
      type: 'REQUEST_SYMBOL',
      tabUrl: tabUrl,
      riskScore: riskScore,
      timestamp: new Date().toISOString()
    });
  }

  // Disconnect
  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.isConnected = false;
      console.log('🔌 WebSocket disconnected');
    }
  }

  // Get connection status
  getStatus() {
    return {
      isConnected: this.isConnected,
      url: this.wsUrl,
      reconnectAttempts: this.reconnectAttempts
    };
  }
}

// Create global instance
window.realtimeWebSocket = null;

// Initialize WebSocket handler
function initializeWebSocketHandler() {
  if (!window.realtimeWebSocket) {
    window.realtimeWebSocket = new RealtimeWebSocketHandler();
    
    // Setup handlers for different message types
    window.realtimeWebSocket.on('SYMBOL_UPDATE', (message) => {
      console.log('🎯 Symbol update from server:', message.symbol);
      
      // Broadcast to popup
      chrome.runtime.sendMessage(message).catch(() => {});
    });

    window.realtimeWebSocket.on('ALERT', (message) => {
      console.log('🚨 Alert from server:', message.data.classification);
      
      // Broadcast to popup
      chrome.runtime.sendMessage({
        type: 'ALERT_UPDATE',
        alert: message.data
      }).catch(() => {});
    });

    window.realtimeWebSocket.on('THREAT_DETECTED', (message) => {
      console.log('⚠️ Threat detected:', message.data.url);
      
      // Show notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '🚨 REAL-TIME THREAT DETECTED',
        message: `${message.data.url}\nRisk: ${message.data.risk_score}%`,
        priority: 2
      });
    });

    window.realtimeWebSocket.on('STATS_UPDATE', (message) => {
      console.log('📊 Statistics update:', message.data);
      
      // Update local stats
      chrome.storage.local.set({
        realtimeStats: message.data
      });
    });

    // Connect to server
    window.realtimeWebSocket.connect();
    
    console.log('✅ WebSocket handler initialized');
  }
  
  return window.realtimeWebSocket;
}

// Make available for background.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = RealtimeWebSocketHandler;
}
