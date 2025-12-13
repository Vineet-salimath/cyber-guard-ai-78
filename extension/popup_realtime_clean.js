// Simple popup script - no complex logic
console.log('[POPUP] Script loaded');

document.addEventListener('DOMContentLoaded', () => {
    console.log('[POPUP] DOM Ready');
    
    // Scan button
    const scanBtn = document.getElementById('scan-button');
    if (scanBtn) {
        scanBtn.addEventListener('click', () => {
            console.log('[POPUP] Scan clicked');
            scanBtn.textContent = 'Scanning...';
            scanBtn.disabled = true;
            
            setTimeout(() => {
                scanBtn.textContent = 'Scan Current Page';
                scanBtn.disabled = false;
            }, 2000);
        });
    }
    
    // Dashboard button
    const dashBtn = document.getElementById('dashboard-button');
    if (dashBtn) {
        dashBtn.addEventListener('click', () => {
            console.log('[POPUP] Dashboard clicked');
            chrome.runtime.openOptionsPage?.();
        });
    }
    
    // Protection toggle
    const protToggle = document.getElementById('protection-toggle');
    if (protToggle) {
        protToggle.addEventListener('change', (e) => {
            console.log('[POPUP] Protection:', e.target.checked);
        });
    }
});
