# Real-Time Symbol & Alert Updates - Quick Reference

## What's New?

The MalwareSnipper extension now features **real-time symbol changes** and **continuous alert updates** that happen instantly as security analysis progresses.

---

## Quick Start (30 seconds)

### 1. Update popup.html
Replace your popup script reference:

```html
<!-- OLD -->
<script src="popup.js"></script>

<!-- NEW -->
<script src="symbolManager.js"></script>
<script src="alertManager.js"></script>
<script src="popup_realtime_enhanced.js"></script>
<link rel="stylesheet" href="realtime_animations.css">
```

### 2. Update manifest.json
Add the new scripts to background:

```json
{
  "background": {
    "service_worker": [
      "symbolManager.js",
      "alertManager.js",
      "background.js"
    ]
  },
  "permissions": [
    "activeTab",
    "webNavigation",
    "tabs",
    "scripting",
    "storage",
    "notifications",
    "action"
  ]
}
```

### 3. Restart Extension
- Go to `chrome://extensions/`
- Toggle off and on the MalwareSnipper extension
- Check console: `chrome://extensions/ → Details → Errors`

---

## Symbol Meanings

| Symbol | Meaning | Risk | Action |
|--------|---------|------|--------|
| ✓ 🟢 | SAFE | 0-40% | Safe to use |
| ⚠ 🟡 | SUSPICIOUS | 40-70% | Review suspicious activity |
| ✗ 🔴 | THREAT | 70-100% | Malware detected - Don't use |
| ⚙️ | SCANNING | During scan | Analyzing... |

---

## Real-Time Features

### 🔄 Symbol Updates
- Badge icon changes **instantly** as analysis progresses
- Color changes: Green → Yellow → Red
- No page refresh needed
- Shows in browser address bar

### 🚨 Alert Updates
- New threats appear in popup **immediately**
- Alert cards show with smooth animation
- Threat count updates in real-time
- Sorted by most recent first

### 📊 Statistics
- Monitored sites count increases in real-time
- Threat count increases as threats detected
- Status indicator updates based on current risk
- Unread alert badge shown

### 📡 Alert Stream
- Continuous background updates (every 2 seconds)
- Threat statistics aggregated
- Critical threats highlighted
- All data persisted for history

---

## API Reference

### SymbolManager

```javascript
// Get symbol for a risk score
SymbolManager.getSymbolByRiskScore(75) // Returns: 'THREAT'

// Update the badge icon
await SymbolManager.updateBadge('THREAT', tabId)

// Update status display in popup
await SymbolManager.updateStatusDisplay('THREAT')

// Send symbol change to popup
await SymbolManager.broadcastSymbolUpdate('THREAT', tabId, {
  riskScore: 75,
  classification: 'MALICIOUS'
})

// Record for trend analysis
SymbolManager.recordSymbolChange('THREAT', 75, 'https://example.com')

// Get symbol history for a URL
SymbolManager.getSymbolTrend('https://example.com')
```

### AlertManager

```javascript
// Create and add alert
await AlertManager.addAlert({
  url: 'https://malicious.com',
  classification: 'MALICIOUS',
  risk_score: 95,
  timestamp: new Date().toISOString()
})

// Subscribe to alert updates
AlertManager.onAlertUpdate((alert) => {
  console.log('New alert:', alert.classification)
})

// Start continuous alert stream
const stopStream = AlertManager.startAlertStream((update) => {
  console.log('Alert stats:', update.stats)
}, 2000) // Every 2 seconds

// Get all alerts
AlertManager.getAlerts(10) // Last 10 alerts

// Get unread count
AlertManager.getUnreadCount()

// Mark as read
AlertManager.markAsRead(alertId)

// Get alert stats
AlertManager.getAlertStats()
// Returns: {total, unread, critical, high, medium, low, malware, phishing}
```

---

## Message Types

### SYMBOL_UPDATE
Sent when icon/symbol changes:
```javascript
{
  type: 'SYMBOL_UPDATE',
  symbol: 'THREAT',
  symbolData: { icon, emoji, color, ... },
  riskScore: 85,
  classification: 'MALICIOUS',
  tabId: 123,
  timestamp: '2025-12-13T10:30:00Z'
}
```

### ALERT_UPDATE
Sent when new threat detected:
```javascript
{
  type: 'ALERT_UPDATE',
  alert: {
    id: 'alert_123',
    url: 'https://malicious.com',
    classification: 'MALICIOUS',
    risk_score: 95,
    severity: 'CRITICAL',
    timestamp: '2025-12-13T10:30:00Z'
  }
}
```

### ALERT_STREAM
Continuous statistics update:
```javascript
{
  type: 'ALERT_STREAM',
  data: {
    alerts: [...],
    stats: {
      total: 25,
      unread: 3,
      critical: 2,
      high: 5,
      medium: 10,
      low: 8
    },
    timestamp: '2025-12-13T10:30:00Z'
  }
}
```

---

## Animations

All animations are in `realtime_animations.css`:

| Animation | Duration | Trigger |
|-----------|----------|---------|
| `pulse` | 2s | Threat status |
| `scanning` | 1.5s | During scan |
| `threatPulse` | 1s | Critical threat |
| `suspiciousPulse` | 1.5s | Suspicious activity |
| `fadeIn` | 0.3s | New alert appears |
| `bounce` | 0.6s | Alert badge |

---

## Chrome Storage Structure

```javascript
// Stats
{
  stats: {
    monitored: 42,
    threats: 3,
    status: 'SAFE',
    currentRisk: 25
  }
}

// Alert Queue
{
  alertQueue: [
    {
      id: 'alert_timestamp_random',
      url: 'https://example.com',
      classification: 'MALICIOUS',
      risk_score: 95,
      severity: 'CRITICAL',
      timestamp: '2025-12-13T10:30:00Z'
    },
    // ... more alerts
  ]
}

// Alert Statistics
{
  alertStats: {
    total: 25,
    unread: 3,
    critical: 2,
    high: 5
  }
}

// Recent Scans (legacy)
{
  recentScans: [
    {
      url: 'https://example.com',
      classification: 'BENIGN',
      risk_score: 15,
      timestamp: '2025-12-13T10:25:00Z'
    }
  ]
}
```

---

## Popup Messages

Listen for messages in popup:

```javascript
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Real-time symbol change
  if (message.type === 'SYMBOL_UPDATE') {
    console.log('Symbol changed to:', message.symbol)
  }
  
  // New threat alert
  if (message.type === 'ALERT_UPDATE') {
    console.log('New alert:', message.alert.classification)
  }
  
  // Continuous stats
  if (message.type === 'ALERT_STREAM') {
    console.log('Stats:', message.data.stats)
  }
})
```

---

## Debugging Checklist

- [ ] Scripts included in manifest.json
- [ ] Permissions include "action" and "notifications"
- [ ] popup.html includes all new script files
- [ ] realtime_animations.css included in popup.html
- [ ] Chrome console shows no errors
- [ ] symbolManager properly initialized
- [ ] alertManager properly initialized
- [ ] Messages being sent (check console logs)
- [ ] Badge updates visible in browser
- [ ] Alerts appear in popup

---

## Performance Tips

1. **Reduce Update Frequency:** Change interval from 2000ms to higher
2. **Limit Alert Queue:** Reduce `maxAlerts` in alertManager.js (default 50)
3. **Disable Animations:** Comment out in realtime_animations.css
4. **Use Caching:** Extend `CACHE_DURATION` in background.js
5. **Batch Updates:** Aggregate alerts before broadcast

---

## Troubleshooting

### Symbols Not Updating
```javascript
// In background.js console:
console.log(SymbolManager) // Check if loaded
SymbolManager.symbols // See all available symbols
```

### Alerts Not Showing
```javascript
// In popup console:
AlertManager.getAlerts() // Check alert queue
AlertManager.getAlertStats() // Check statistics
```

### Messages Not Received
```javascript
// In popup console:
chrome.runtime.onMessage.addListener((msg) => {
  console.log('📬 Message:', msg)
})
```

### WebSocket Not Connecting
```javascript
// In background console:
window.realtimeWebSocket.getStatus() // Check connection
window.realtimeWebSocket.connect() // Try reconnecting
```

---

## Integration Examples

### In background.js (After scan):
```javascript
// Determine symbol
const symbolKey = SymbolManager.getSymbolByRiskScore(riskScore)

// Update badge
await SymbolManager.updateBadge(symbolKey, tabId)

// Create alert
await AlertManager.addAlert({
  url: pageUrl,
  classification: result.classification,
  risk_score: riskScore,
  timestamp: new Date().toISOString()
})
```

### In popup.js (Message listener):
```javascript
if (message.type === 'SYMBOL_UPDATE') {
  handleSymbolUpdate(message)
  // Update UI with new symbol colors
}

if (message.type === 'ALERT_UPDATE') {
  handleAlertUpdate(message)
  // Add alert to list with animation
}
```

---

## Update Intervals Reference

| Component | Frequency | Purpose |
|-----------|-----------|---------|
| Symbol Badge | Instant | Show current status |
| Popup UI | 2s | Refresh display |
| Storage Sync | Per event | Save changes |
| Connection Check | 5s | Verify backend |
| Alert Stream | 2s | Aggregated stats |

---

## Files Overview

```
extension/
├── symbolManager.js              ← Symbol/icon management
├── alertManager.js               ← Alert queue management
├── popup_realtime_enhanced.js    ← Enhanced popup UI
├── realtimeWebSocket.js          ← WebSocket handler
├── realtime_animations.css       ← Real-time animations
├── background.js                 ← Integration (updated)
├── manifest.json                 ← Updated with permissions
└── REALTIME_INTEGRATION_GUIDE.md ← Full documentation
```

---

## Version Info

- **System:** MalwareSnipper v1.0.0
- **Feature:** Real-Time Symbol & Alert Updates
- **Status:** Production Ready ✅
- **Date:** December 13, 2025

---

**Need help?** Check REALTIME_INTEGRATION_GUIDE.md for detailed documentation!
