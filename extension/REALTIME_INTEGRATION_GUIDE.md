# Real-Time Symbol & Alert Updates Implementation Guide

## Overview

This guide explains the new real-time symbol (icon) and alert update system that has been implemented in the MalwareSnipper extension. The system ensures that:

1. **Symbols/Icons change in real-time** based on continuous security analysis
2. **Alerts are updated instantly** as threats are detected
3. **Status displays update** without requiring page refreshes
4. **Connection is maintained** via WebSocket for continuous updates

---

## Architecture

### Components

#### 1. **symbolManager.js** ⚙️
Manages all symbol/icon changes based on threat analysis.

**Features:**
- Converts risk scores to visual symbols (✓, ⚠, ✗)
- Updates browser badge in real-time
- Tracks symbol history for trend analysis
- Broadcasts symbol changes to all components
- Provides emoji indicators for different threat levels

**Key Methods:**
```javascript
// Get symbol based on risk score
SymbolManager.getSymbolByRiskScore(riskScore)

// Update extension badge
await SymbolManager.updateBadge(symbolKey, tabId)

// Update status display
await SymbolManager.updateStatusDisplay(symbolKey)

// Broadcast symbol update
await SymbolManager.broadcastSymbolUpdate(symbolKey, tabId, data)

// Record symbol changes for trend analysis
SymbolManager.recordSymbolChange(symbolKey, riskScore, tabUrl)
```

#### 2. **alertManager.js** 🚨
Manages continuous alert stream and notification system.

**Features:**
- Creates and manages alert queue
- Persists alerts to storage
- Calculates alert severity
- Provides real-time alert stream
- Filters alerts by type and severity
- Generates HTML for alert display

**Key Methods:**
```javascript
// Add alert to queue
await AlertManager.addAlert(alertData)

// Subscribe to alerts
AlertManager.onAlertUpdate(callback)

// Start continuous alert stream
AlertManager.startAlertStream(updateCallback, interval)

// Get alerts by severity
AlertManager.getAlertsBySeverity(severity)

// Get unread count
AlertManager.getUnreadCount()

// Get alert statistics
AlertManager.getAlertStats()
```

#### 3. **background.js** (Enhanced)
Central processing for scans and real-time updates.

**Enhancements:**
- Integrates SymbolManager for icon updates
- Integrates AlertManager for alert creation
- Sends real-time messages to popup
- Records all symbol changes
- Maintains continuous update loop

**Flow:**
```
URL Scan → Backend Analysis → Result Processing
                                   ↓
                        SymbolManager.updateBadge()
                                   ↓
                        AlertManager.addAlert()
                                   ↓
                    Broadcast to Popup/Content Scripts
```

#### 4. **popup_realtime_enhanced.js** 🎨
Enhanced popup with real-time integration.

**Features:**
- Listens for SYMBOL_UPDATE messages
- Listens for ALERT_UPDATE messages
- Listens for ALERT_STREAM updates
- Updates UI without page refresh
- Shows new alerts with animation
- Displays threat statistics

**Message Handlers:**
```javascript
// Handle real-time symbol changes
handleSymbolUpdate(message)

// Handle real-time alert creation
handleAlertUpdate(message)

// Handle continuous alert stream
handleAlertStream(message)
```

#### 5. **realtimeWebSocket.js** 🔌
WebSocket connection for server-to-client updates (optional advanced feature).

**Features:**
- Establishes persistent WebSocket connection
- Auto-reconnect with exponential backoff
- Broadcasts server messages to all listeners
- Queues messages when disconnected
- Supports custom message handlers

---

## How It Works

### Real-Time Symbol Updates

1. **User visits a website**
2. **Background script captures page data**
3. **Data sent to backend for analysis**
4. **Backend returns risk score (0-100)**
5. **SymbolManager determines symbol:**
   - 0-40: SAFE (✓ 🟢)
   - 40-70: SUSPICIOUS (⚠ 🟡)
   - 70-100: THREAT (✗ 🔴)
6. **Badge icon updates immediately** in extension
7. **Symbol broadcasted to popup** for display update
8. **Change recorded** for trend analysis

### Real-Time Alert Flow

1. **Threat analysis complete**
2. **AlertManager creates alert object:**
   ```javascript
   {
     id: unique_id,
     url: scanned_url,
     classification: MALICIOUS/SUSPICIOUS/BENIGN,
     risk_score: 0-100,
     timestamp: ISO_string,
     severity: CRITICAL/HIGH/MEDIUM/LOW,
     threatType: Malware/Phishing/Suspicious Activity
   }
   ```
3. **Alert added to in-memory queue**
4. **Alert persisted to Chrome storage**
5. **Popup receives ALERT_UPDATE message**
6. **New alert appears with animation**
7. **Alert stats updated** (total, unread, by severity)

---

## Integration Points

### Using in background.js

```javascript
// Initialize at startup
const SymbolManager = require('./symbolManager.js');
const AlertManager = require('./alertManager.js');

// After scan analysis
const riskScore = analysisResult.risk_score;
const symbolKey = SymbolManager.getSymbolByRiskScore(riskScore);

// Update badge
await SymbolManager.updateBadge(symbolKey, tabId);

// Add alert
await AlertManager.addAlert({
  url: url,
  classification: classification,
  risk_score: riskScore,
  timestamp: new Date().toISOString()
});
```

### Listening in popup.js

```javascript
// Listen for symbol updates
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SYMBOL_UPDATE') {
    handleSymbolUpdate(message);
  }
  if (message.type === 'ALERT_UPDATE') {
    handleAlertUpdate(message);
  }
});
```

### Real-Time Alert Streaming

```javascript
// Start continuous updates (backend)
AlertManager.startAlertStream((update) => {
  chrome.runtime.sendMessage({
    type: 'ALERT_STREAM',
    data: update
  });
}, 2000); // Every 2 seconds
```

---

## Manifest Configuration

The manifest.json has been updated to include:

```json
{
  "permissions": [
    "activeTab",
    "webNavigation",
    "tabs",
    "scripting",
    "storage",
    "notifications",
    "action"
  ],
  "background": {
    "service_worker": "symbolManager.js",
    "service_worker": "alertManager.js",
    "service_worker": "background.js"
  }
}
```

---

## Real-Time Animations

The system includes CSS animations for visual feedback:

**File:** `realtime_animations.css`

### Available Animations

| Animation | Use Case | Speed |
|-----------|----------|-------|
| `pulse` | Threat status pulsing | 2s |
| `scanning` | While scanning active | 1.5s |
| `threatPulse` | Critical threat alert | 1s |
| `suspiciousPulse` | Suspicious activity | 1.5s |
| `fadeIn` | New alert appearance | 0.3s |
| `bounce` | Alert badge bounce | 0.6s |

### Example: Adding to popup.html

```html
<link rel="stylesheet" href="realtime_animations.css">
```

---

## Update Intervals

| Component | Update Frequency | Purpose |
|-----------|------------------|---------|
| Symbol Badge | Real-time (instant) | Immediate visual feedback |
| Alert Popup | Real-time (instant) | Show new threats |
| Stats Counter | 2 seconds | Display aggregated stats |
| Connection Check | 5 seconds | Verify backend health |
| Storage Sync | Per alert | Persistent data |

---

## Symbol Types and States

### SAFE (Risk 0-40)
```javascript
{
  icon: '✓',
  emoji: '🟢',
  color: '#00ff88',
  badgeText: '✓',
  badgeColor: '#00ff88',
  title: 'SAFE',
  animationClass: 'symbol-safe'
}
```

### SUSPICIOUS (Risk 40-70)
```javascript
{
  icon: '⚠',
  emoji: '🟡',
  color: '#ffc107',
  badgeText: '!',
  badgeColor: '#ffc107',
  title: 'SUSPICIOUS',
  animationClass: 'symbol-suspicious'
}
```

### THREAT (Risk 70-100)
```javascript
{
  icon: '✗',
  emoji: '🔴',
  color: '#ff5252',
  badgeText: '✗',
  badgeColor: '#ff5252',
  title: 'THREAT',
  animationClass: 'symbol-threat'
}
```

### SCANNING
```javascript
{
  icon: '◉',
  emoji: '⚙️',
  color: '#2196f3',
  badgeText: '○',
  badgeColor: '#2196f3',
  title: 'SCANNING',
  animationClass: 'symbol-scanning'
}
```

---

## Alert Severity Levels

| Severity | Risk Range | Color | Use |
|----------|-----------|-------|-----|
| CRITICAL | 80-100 | Red (#ff1744) | Immediate action needed |
| HIGH | 60-79 | Orange-Red (#ff5252) | Investigate urgently |
| MEDIUM | 40-59 | Yellow (#ffc107) | Review soon |
| LOW | 0-39 | Light Orange (#ffb74d) | Monitor |

---

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    User Visits URL                      │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│             background.js - capturePageData             │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│         Backend API - /api/scan-realtime                │
│         Returns: risk_score, classification              │
└────────────────────┬────────────────────────────────────┘
                     ↓
        ┌────────────┴────────────┐
        ↓                         ↓
┌──────────────────┐    ┌─────────────────────┐
│  SymbolManager   │    │   AlertManager      │
│                  │    │                     │
│ • Get Symbol     │    │ • Create Alert      │
│ • Update Badge   │    │ • Add to Queue      │
│ • Broadcast      │    │ • Persist Storage   │
│ • Record History │    │ • Broadcast         │
└────────┬─────────┘    └──────────┬──────────┘
         │                         │
         └────────────┬────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│      chrome.runtime.sendMessage()                        │
│      Message Types:                                      │
│      • SYMBOL_UPDATE                                    │
│      • ALERT_UPDATE                                     │
│      • ALERT_STREAM                                     │
└────────────────────┬────────────────────────────────────┘
                     ↓
        ┌────────────┴────────────┐
        ↓                         ↓
┌─────────────────┐    ┌──────────────────────┐
│  popup.js       │    │  content-script.js   │
│                 │    │                      │
│ • Update UI     │    │ • Page notifications │
│ • Show Alerts   │    │ • Inline warnings    │
│ • Update Stats  │    │ • Block malicious    │
│ • Animations    │    │ • Custom styling     │
└─────────────────┘    └──────────────────────┘
```

---

## Testing Real-Time Updates

### Manual Testing Steps

1. **Start the extension:**
   ```
   chrome://extensions/
   Load unpacked → Select extension folder
   ```

2. **Open popup:**
   - Click extension icon
   - Monitor console for real-time messages

3. **Visit test URLs:**
   - Safe: amazon.com
   - Suspicious: example.com (will simulate)
   - Threat: (use test cases from backend)

4. **Observe real-time changes:**
   - Badge icon should change immediately
   - Status card should update with color
   - New alerts should appear in list
   - Animations should play

### Console Debugging

```javascript
// In popup console:
chrome.runtime.onMessage.addListener((msg) => {
  console.log('📬 Message:', msg.type, msg);
});
```

---

## Performance Considerations

1. **Message Frequency:** Limited to 2-5 second intervals
2. **Storage:** Alerts stored in Chrome.storage.local (10MB limit)
3. **Memory:** Alert queue limited to 50 entries
4. **CPU:** CSS animations use transform (GPU accelerated)
5. **Network:** WebSocket keeps persistent connection

---

## Troubleshooting

### Symbols Not Updating
- Check: `SymbolManager.recordSymbolChange()` is being called
- Verify: `chrome.action.setBadgeText()` permissions in manifest
- Debug: Console logs for "Symbol updated to:"

### Alerts Not Showing
- Check: `AlertManager.addAlert()` is being called
- Verify: Chrome storage permissions in manifest
- Debug: `AlertManager.getAlerts()` in console

### WebSocket Not Connecting
- Start: `node backend/websocket_server.py`
- Verify: Port 8080 is accessible
- Check: `realtimeWebSocket.connect()` initialization

### Performance Issues
- Reduce alert update frequency
- Limit alert queue size
- Disable animations if needed
- Check: Browser CPU usage

---

## Future Enhancements

1. **WebSocket Integration:** Full server-to-client real-time updates
2. **Custom Alerts:** User-configurable threat thresholds
3. **Trend Analysis:** Show symbol/threat trends over time
4. **Batch Updates:** Aggregate multiple alerts
5. **Dashboard Integration:** Real-time dashboard updates
6. **Mobile Support:** Send alerts to mobile device
7. **Custom Symbols:** User-defined icon sets

---

## Files Created/Modified

### New Files Created
- `symbolManager.js` - Symbol management system
- `alertManager.js` - Alert queue and management
- `popup_realtime_enhanced.js` - Enhanced popup with real-time updates
- `realtimeWebSocket.js` - WebSocket handler
- `realtime_animations.css` - Real-time animations
- `REALTIME_INTEGRATION_GUIDE.md` - This file

### Files Modified
- `background.js` - Added real-time update integration
- `manifest.json` - Added new permissions and scripts

---

## Support & Debugging

For issues, check:
1. Browser console for errors: `F12 → Console`
2. Extension logs: `chrome://extensions/ → Details`
3. Backend logs: `python backend/app.py`
4. Storage: `chrome://extensions/ → Details → Manage storage`

---

## Version History

- **v1.0.0** (Dec 2025): Initial real-time symbol & alert system
  - Real-time symbol updates
  - Continuous alert stream
  - CSS animations
  - WebSocket support

---

**Last Updated:** December 13, 2025  
**Status:** Production Ready ✅
