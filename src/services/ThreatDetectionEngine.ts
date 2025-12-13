/**
 * Real-Time Threat Detection Engine
 * Respects security configuration toggles in real-time
 */

import { securityConfigManager } from './SecurityConfigurationManager';

export interface ThreatData {
  url: string;
  type: string;
  severity: number; // 0-10 scale
  timestamp: number;
  scanId: string;
  isThreaten: boolean;
}

export interface ScanLog {
  scanId: string;
  url: string;
  threatData: ThreatData | null;
  duration: number;
  timestamp: number;
}

class ThreatDetectionEngine {
  private activeScans: Map<string, Promise<ThreatData | null>> = new Map();
  private scanLogs: ScanLog[] = [];
  private readonly MAX_CONCURRENT_SCANS = 5;
  private currentScans = 0;
  private notificationCallbacks: ((data: ThreatData) => void)[] = [];
  private blockingCallbacks: ((url: string, data: ThreatData) => void)[] = [];
  
  constructor() {
    // Subscribe to configuration changes
    securityConfigManager.subscribe((change) => {
      if (change.setting === 'automaticScanning' && !change.newValue) {
        console.log('[ThreatEngine] Automatic scanning disabled, clearing pending scans');
        this.clearPendingScans();
      }
    });
  }
  
  /**
   * Register callback for threat notifications
   */
  onThreatDetected(callback: (data: ThreatData) => void): () => void {
    this.notificationCallbacks.push(callback);
    
    return () => {
      this.notificationCallbacks = this.notificationCallbacks.filter(cb => cb !== callback);
    };
  }
  
  /**
   * Register callback for blocking requests
   */
  onBlockingRequired(callback: (url: string, data: ThreatData) => void): () => void {
    this.blockingCallbacks.push(callback);
    
    return () => {
      this.blockingCallbacks = this.blockingCallbacks.filter(cb => cb !== callback);
    };
  }
  
  /**
   * Scan URL with real-time toggle respect
   */
  async scanURL(url: string, context: Record<string, any> = {}): Promise<ThreatData | null> {
    // Check if automatic scanning is enabled
    if (!securityConfigManager.getSetting('automaticScanning')) {
      console.debug('[ThreatEngine] Automatic scanning disabled, skipping scan');
      return null;
    }
    
    // Prevent duplicate scans
    if (this.activeScans.has(url)) {
      return this.activeScans.get(url)!;
    }
    
    const scanId = this.generateScanId();
    const scanPromise = this.executeScan(url, scanId, context);
    
    this.activeScans.set(url, scanPromise);
    
    try {
      const result = await scanPromise;
      return result;
    } finally {
      this.activeScans.delete(url);
    }
  }
  
  /**
   * Execute threat scan against URL
   */
  private async executeScan(
    url: string,
    scanId: string,
    context: Record<string, any>
  ): Promise<ThreatData | null> {
    const scanStartTime = Date.now();
    
    // Throttle concurrent scans
    while (this.currentScans >= this.MAX_CONCURRENT_SCANS) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    this.currentScans++;
    
    try {
      // Call backend API for threat analysis
      const threatData = await this.fetchThreatAnalysis(url, scanId);
      const duration = Date.now() - scanStartTime;
      
      // Log scan
      this.logScan(scanId, url, threatData, duration);
      
      // Handle threats based on current configuration
      if (threatData && threatData.isThreaten) {
        await this.handleThreatDetection(url, threatData);
      }
      
      return threatData;
      
    } catch (error) {
      console.error(`[ThreatEngine] Scan failed for ${url}:`, error);
      const duration = Date.now() - scanStartTime;
      this.logScan(scanId, url, null, duration);
      return null;
      
    } finally {
      this.currentScans--;
    }
  }
  
  /**
   * Fetch threat analysis from backend
   */
  private async fetchThreatAnalysis(url: string, scanId: string): Promise<ThreatData | null> {
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url,
          scanId: scanId,
          timestamp: Date.now()
        })
      });
      
      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }
      
      const data = await response.json();
      
      return {
        url: url,
        type: data.threat_type || 'UNKNOWN',
        severity: data.threat_score || 0,
        timestamp: Date.now(),
        scanId: scanId,
        isThreaten: (data.classification || 'BENIGN') !== 'BENIGN'
      };
      
    } catch (error) {
      console.error('[ThreatEngine] Failed to fetch threat analysis:', error);
      return null;
    }
  }
  
  /**
   * Handle detected threats based on current configuration
   */
  private async handleThreatDetection(url: string, threatData: ThreatData): Promise<void> {
    const settings = securityConfigManager.getAllSettings();
    
    // Always log threats internally regardless of settings
    console.warn(`[ThreatEngine] Threat detected: ${threatData.type} (Severity: ${threatData.severity})`);
    
    // Conditional blocking - check toggle in real-time
    if (settings.blockMalicious && threatData.severity >= 7) {
      console.error(`[ThreatEngine] BLOCKING URL: ${url}`);
      await this.executeBlocking(url, threatData);
    }
    
    // Conditional alerting - check toggle in real-time
    if (settings.threatAlerts) {
      console.log('[ThreatEngine] Sending threat notification');
      await this.sendThreatNotification(threatData);
    }
    
    // Trigger incident response for critical threats
    if (threatData.severity >= 9) {
      console.error('[ThreatEngine] CRITICAL THREAT - Initiating incident response');
      await this.initiateIncidentResponse(url, threatData);
    }
  }
  
  /**
   * Execute blocking for malicious URL
   */
  private async executeBlocking(url: string, threatData: ThreatData): Promise<void> {
    this.blockingCallbacks.forEach(callback => {
      try {
        callback(url, threatData);
      } catch (error) {
        console.error('Error in blocking callback:', error);
      }
    });
    
    // Send blocking event to backend
    try {
      await fetch('/api/scanner/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: url,
          threat: threatData.type,
          severity: threatData.severity,
          timestamp: Date.now()
        })
      });
    } catch (error) {
      console.error('Failed to log blocking event:', error);
    }
  }
  
  /**
   * Send threat notification to user
   */
  private async sendThreatNotification(threatData: ThreatData): Promise<void> {
    this.notificationCallbacks.forEach(callback => {
      try {
        callback(threatData);
      } catch (error) {
        console.error('Error in notification callback:', error);
      }
    });
  }
  
  /**
   * Initiate incident response for critical threats
   */
  private async initiateIncidentResponse(url: string, threatData: ThreatData): Promise<void> {
    try {
      await fetch('/api/scanner/incident', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: url,
          threat: threatData.type,
          severity: threatData.severity,
          timestamp: Date.now()
        })
      });
    } catch (error) {
      console.error('Failed to initiate incident response:', error);
    }
  }
  
  /**
   * Log scan results
   */
  private logScan(
    scanId: string,
    url: string,
    threatData: ThreatData | null,
    duration: number
  ): void {
    const log: ScanLog = {
      scanId,
      url,
      threatData,
      duration,
      timestamp: Date.now()
    };
    
    this.scanLogs.push(log);
    
    // Keep only last 1000 logs
    if (this.scanLogs.length > 1000) {
      this.scanLogs = this.scanLogs.slice(-1000);
    }
  }
  
  /**
   * Clear pending scans
   */
  private clearPendingScans(): void {
    this.activeScans.clear();
    console.log('[ThreatEngine] Cleared pending scans');
  }
  
  /**
   * Generate unique scan ID
   */
  private generateScanId(): string {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  /**
   * Get scan logs
   */
  getScanLogs(): ScanLog[] {
    return [...this.scanLogs];
  }
  
  /**
   * Get active scans count
   */
  getActiveScanCount(): number {
    return this.activeScans.size;
  }
  
  /**
   * Clear all logs
   */
  clearLogs(): void {
    this.scanLogs = [];
  }
}

// Export singleton instance
let threatEngineInstance: ThreatDetectionEngine;

export function getThreatDetectionEngine(): ThreatDetectionEngine {
  if (!threatEngineInstance) {
    threatEngineInstance = new ThreatDetectionEngine();
  }
  return threatEngineInstance;
}

export default ThreatDetectionEngine;
