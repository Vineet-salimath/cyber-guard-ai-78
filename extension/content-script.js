// ═══════════════════════════════════════════════════════════════════════════
// MALWARE SNIPPER - ADVANCED CONTENT SCRIPT
// Real-time DOM analysis, JS extraction, and metadata capture
// ═══════════════════════════════════════════════════════════════════════════

console.log('🔍 [CONTENT SCRIPT] Malware Snipper Active - Analyzing page...');

const BACKEND_URL = 'http://localhost:5000';
const ANALYSIS_DELAY = 2000; // Wait 2 seconds for page to load

// ═══════════════════════════════════════════════════════════════════════════
// PAGE METADATA EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════

function extractPageMetadata() {
    const metadata = {
        url: window.location.href,
        title: document.title,
        domain: window.location.hostname,
        protocol: window.location.protocol,
        timestamp: Date.now(),
        
        // HTML metadata
        metaTags: extractMetaTags(),
        headings: extractHeadings(),
        links: extractLinks(),
        forms: extractForms(),
        
        // Page characteristics
        documentSize: document.documentElement.innerHTML.length,
        scriptCount: document.scripts.length,
        iframeCount: document.querySelectorAll('iframe').length,
        imgCount: document.images.length,
        
        // Security indicators
        hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0,
        hasHiddenForms: document.querySelectorAll('form[hidden], form[style*="display:none"]').length > 0,
        hasExternalScripts: countExternalScripts(),
        
        // Suspicious patterns
        suspiciousPatterns: detectSuspiciousPatterns()
    };
    
    console.log('📊 [METADATA] Extracted page metadata:', metadata);
    return metadata;
}

function extractMetaTags() {
    const metaTags = {};
    document.querySelectorAll('meta').forEach(meta => {
        const name = meta.getAttribute('name') || meta.getAttribute('property');
        const content = meta.getAttribute('content');
        if (name && content) {
            metaTags[name] = content;
        }
    });
    return metaTags;
}

function extractHeadings() {
    const headings = [];
    document.querySelectorAll('h1, h2, h3').forEach(h => {
        headings.push({
            tag: h.tagName,
            text: h.textContent.substring(0, 100)
        });
    });
    return headings.slice(0, 10); // Limit to first 10
}

function extractLinks() {
    const links = [];
    document.querySelectorAll('a[href]').forEach(link => {
        const href = link.href;
        if (href && !href.startsWith('javascript:')) {
            links.push({
                text: link.textContent.substring(0, 50),
                href: href,
                external: !href.startsWith(window.location.origin)
            });
        }
    });
    return links.slice(0, 20); // Limit to first 20
}

function extractForms() {
    const forms = [];
    document.querySelectorAll('form').forEach(form => {
        forms.push({
            action: form.action,
            method: form.method,
            hasPassword: form.querySelectorAll('input[type="password"]').length > 0,
            inputCount: form.querySelectorAll('input').length,
            hidden: form.hidden || form.style.display === 'none'
        });
    });
    return forms;
}

function countExternalScripts() {
    let externalCount = 0;
    document.querySelectorAll('script[src]').forEach(script => {
        if (!script.src.startsWith(window.location.origin)) {
            externalCount++;
        }
    });
    return externalCount;
}

// ═══════════════════════════════════════════════════════════════════════════
// JAVASCRIPT CODE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════

function extractJavaScriptCode() {
    const jsAnalysis = {
        inlineScripts: [],
        externalScripts: [],
        eventHandlers: [],
        obfuscationIndicators: {
            hasEval: false,
            hasBase64: false,
            hasFromCharCode: false,
            hasUnescape: false,
            hasHexEncoding: false,
            suspiciousVariableNames: []
        }
    };
    
    // Analyze inline scripts
    document.querySelectorAll('script:not([src])').forEach((script, index) => {
        const code = script.textContent;
        if (code.trim().length > 0) {
            const analysis = analyzeJavaScriptCode(code);
            jsAnalysis.inlineScripts.push({
                id: `inline-${index}`,
                length: code.length,
                preview: code.substring(0, 200),
                ...analysis
            });
            
            // Update obfuscation indicators
            mergeObfuscationIndicators(jsAnalysis.obfuscationIndicators, analysis);
        }
    });
    
    // Track external scripts
    document.querySelectorAll('script[src]').forEach(script => {
        jsAnalysis.externalScripts.push({
            src: script.src,
            async: script.async,
            defer: script.defer,
            crossOrigin: script.crossOrigin
        });
    });
    
    // Extract event handlers
    jsAnalysis.eventHandlers = extractEventHandlers();
    
    console.log('💻 [JS ANALYSIS] JavaScript code analyzed:', jsAnalysis);
    return jsAnalysis;
}

function analyzeJavaScriptCode(code) {
    const analysis = {
        hasEval: /eval\s*\(/.test(code),
        hasBase64: /atob\s*\(|btoa\s*\(/.test(code),
        hasFromCharCode: /fromCharCode/.test(code),
        hasUnescape: /unescape\s*\(/.test(code),
        hasHexEncoding: /\\x[0-9a-fA-F]{2}/.test(code),
        hasObfuscation: false,
        suspiciousPatterns: []
    };
    
    // Check for common obfuscation patterns
    if (code.match(/[a-zA-Z_$][a-zA-Z0-9_$]{50,}/)) {
        analysis.suspiciousPatterns.push('Long variable names (possible obfuscation)');
        analysis.hasObfuscation = true;
    }
    
    if ((code.match(/\[/g) || []).length > 50) {
        analysis.suspiciousPatterns.push('Excessive array access (possible obfuscation)');
        analysis.hasObfuscation = true;
    }
    
    // Detect common malicious patterns
    const maliciousPatterns = [
        { pattern: /document\.write\s*\(/, name: 'document.write()' },
        { pattern: /location\.replace\s*\(/, name: 'location.replace()' },
        { pattern: /\.innerHTML\s*=/, name: 'innerHTML assignment' },
        { pattern: /crypto|mining|coinhive/i, name: 'Cryptomining keywords' },
        { pattern: /keylog|keypress/i, name: 'Keylogging indicators' }
    ];
    
    maliciousPatterns.forEach(({ pattern, name }) => {
        if (pattern.test(code)) {
            analysis.suspiciousPatterns.push(name);
        }
    });
    
    return analysis;
}

function mergeObfuscationIndicators(target, source) {
    target.hasEval = target.hasEval || source.hasEval;
    target.hasBase64 = target.hasBase64 || source.hasBase64;
    target.hasFromCharCode = target.hasFromCharCode || source.hasFromCharCode;
    target.hasUnescape = target.hasUnescape || source.hasUnescape;
    target.hasHexEncoding = target.hasHexEncoding || source.hasHexEncoding;
}

function extractEventHandlers() {
    const handlers = [];
    const elements = document.querySelectorAll('*');
    
    elements.forEach(el => {
        Array.from(el.attributes).forEach(attr => {
            if (attr.name.startsWith('on')) {
                handlers.push({
                    element: el.tagName,
                    event: attr.name,
                    handler: attr.value.substring(0, 100)
                });
            }
        });
    });
    
    return handlers.slice(0, 20); // Limit to first 20
}

// ═══════════════════════════════════════════════════════════════════════════
// NETWORK REQUESTS MONITORING
// ═══════════════════════════════════════════════════════════════════════════

function captureNetworkRequests() {
    const requests = [];
    
    // Override fetch
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
        const url = args[0];
        requests.push({
            type: 'fetch',
            url: url,
            timestamp: Date.now()
        });
        console.log('🌐 [NETWORK] Fetch captured:', url);
        return originalFetch.apply(this, args);
    };
    
    // Override XMLHttpRequest
    const originalOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        requests.push({
            type: 'xhr',
            method: method,
            url: url,
            timestamp: Date.now()
        });
        console.log('🌐 [NETWORK] XHR captured:', method, url);
        return originalOpen.apply(this, arguments);
    };
    
    return requests;
}

// ═══════════════════════════════════════════════════════════════════════════
// SUSPICIOUS PATTERN DETECTION
// ═══════════════════════════════════════════════════════════════════════════

function detectSuspiciousPatterns() {
    const patterns = [];
    
    // Check for suspicious URLs in href attributes
    const suspiciousUrlPatterns = [
        /data:text\/html/i,
        /javascript:/i,
        /vbscript:/i,
        /file:/i
    ];
    
    document.querySelectorAll('a[href], iframe[src]').forEach(el => {
        const url = el.href || el.src;
        suspiciousUrlPatterns.forEach(pattern => {
            if (pattern.test(url)) {
                patterns.push({
                    type: 'suspicious_url',
                    element: el.tagName,
                    url: url.substring(0, 100)
                });
            }
        });
    });
    
    // Check for hidden iframes
    document.querySelectorAll('iframe').forEach(iframe => {
        if (iframe.style.display === 'none' || iframe.hidden || 
            iframe.width === '0' || iframe.height === '0') {
            patterns.push({
                type: 'hidden_iframe',
                src: iframe.src
            });
        }
    });
    
    // Check for suspicious form actions
    document.querySelectorAll('form[action]').forEach(form => {
        const action = form.action;
        if (!action.startsWith(window.location.origin) && action !== '') {
            patterns.push({
                type: 'external_form',
                action: action
            });
        }
    });
    
    return patterns;
}

// ═══════════════════════════════════════════════════════════════════════════
// DOM SNAPSHOT
// ═══════════════════════════════════════════════════════════════════════════

function captureDOMSnapshot() {
    return {
        htmlLength: document.documentElement.innerHTML.length,
        bodyLength: document.body ? document.body.innerHTML.length : 0,
        elementsCount: document.getElementsByTagName('*').length,
        textContent: document.body ? document.body.textContent.substring(0, 1000) : '',
        
        // Security-relevant elements
        iframeCount: document.querySelectorAll('iframe').length,
        objectCount: document.querySelectorAll('object, embed').length,
        scriptCount: document.querySelectorAll('script').length,
        formCount: document.querySelectorAll('form').length
    };
}

// ═══════════════════════════════════════════════════════════════════════════
// SEND DATA TO BACKEND
// ═══════════════════════════════════════════════════════════════════════════

async function sendAnalysisToBackend(data) {
    try {
        console.log('📤 [SEND] Sending analysis to backend...');
        
        const response = await fetch(`${BACKEND_URL}/api/scan-page`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (response.ok) {
            const result = await response.json();
            console.log('✅ [SEND] Analysis sent successfully:', result);
            
            // Send message to extension popup
            chrome.runtime.sendMessage({
                type: 'scan_complete',
                data: result
            });
            
            return result;
        } else {
            console.error('❌ [SEND] Backend error:', response.status);
        }
    } catch (error) {
        console.error('❌ [SEND] Network error:', error);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN ANALYSIS EXECUTION
// ═══════════════════════════════════════════════════════════════════════════

function performFullPageAnalysis() {
    console.log('🔬 [ANALYSIS] Starting full page analysis...');
    
    const analysisData = {
        metadata: extractPageMetadata(),
        javascript: extractJavaScriptCode(),
        dom: captureDOMSnapshot(),
        timestamp: Date.now()
    };
    
    // Send to backend for ML analysis
    sendAnalysisToBackend(analysisData);
    
    console.log('✅ [ANALYSIS] Analysis complete');
}

// Run analysis after page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(performFullPageAnalysis, ANALYSIS_DELAY);
    });
} else {
    setTimeout(performFullPageAnalysis, ANALYSIS_DELAY);
}

// ═══════════════════════════════════════════════════════════════════════════
// SCAN RESULT HANDLER - Process results from background script
// ═══════════════════════════════════════════════════════════════════════════

// Listen for scan results from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('📨 [CONTENT] Message received:', message.type);
  if (message.type === 'SCAN_COMPLETE') {
    console.log('✅ [CONTENT] Handling scan result:', message.data);
    handleScanResult(message.data);
    sendResponse({ success: true });
  } else if (message.type === 'scan_page') {
    console.log('🔄 [MANUAL] Manual scan requested');
    performFullPageAnalysis();
    sendResponse({ success: true });
  }
});

function handleScanResult(scanData) {
  const { url, status, riskScore, threats } = scanData;
  console.log('🔍 [SCAN RESULT] Status:', status, 'RiskScore:', riskScore, 'URL:', url);
  
  if (status === 'SAFE') {
    // Silent - no popup for safe websites
    console.log('✅ SAFE URL - No popup shown');
    return;
  }
  else if (status === 'SUSPICIOUS') {
    // Show suspicious warning and ASK USER for choice
    const userChoice = confirm(`⚠️ MalwareSnipper says:\n\nThe tested URL is SUSPICIOUS!\n\nURL: ${url}\nRisk Score: ${riskScore}/100\n\nThis website may be risky.\n\n⚠️ Click OK to CONTINUE ANYWAY\n⚠️ Click CANCEL to GO BACK TO GOOGLE`);
    
    if (userChoice) {
      // User chose to continue anyway
      logNotification(url, status, riskScore, 'SUSPICIOUS_USER_CONTINUED');
      // Stay on page - do nothing
    } else {
      // User chose to go back
      logNotification(url, status, riskScore, 'SUSPICIOUS_USER_REDIRECTED');
      window.location.href = 'https://google.com';
    }
  } 
  else if (status === 'THREAT' || status === 'MALICIOUS') {
    // Show malicious/threat alert and AUTO-REDIRECT (no choice)
    const threatList = threats && threats.length > 0 ? threats.join(', ') : 'Multiple threats detected';
    
    alert(`🛑 MalwareSnipper says:\n\nThe tested URL is MALICIOUS!\n\nURL: ${url}\nRisk Score: ${riskScore}/100\nThreats Detected: ${threatList}\n\nThis website is dangerous and has been blocked. Redirecting to Google immediately...`);
    
    logNotification(url, status, riskScore, 'MALICIOUS_BLOCKED_REDIRECTED');
    
    // Auto-redirect to Google (no user choice)
    window.location.href = 'https://google.com';
  }
}

function logNotification(url, status, riskScore, action) {
  fetch('http://localhost:5000/api/log-notification', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: url,
      status: status,
      risk_score: riskScore,
      user_action: action,
      timestamp: new Date().toISOString()
    })
  }).catch(err => console.error('Failed to log:', err));
}

console.log('✅ [CONTENT SCRIPT] Ready for analysis');
