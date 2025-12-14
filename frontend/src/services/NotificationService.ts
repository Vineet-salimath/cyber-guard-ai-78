/**
 * Real-Time Notification Service
 * Respects threat alerts toggle and manages notifications
 */

import { securityConfigManager } from './SecurityConfigurationManager';
import type { ThreatData } from './ThreatDetectionEngine';

export interface NotificationOptions {
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'error';
  duration?: number;
  action?: {
    label: string;
    callback: () => void;
  };
}

type NotificationCallback = (notification: NotificationOptions) => void;

class NotificationService {
  private notificationCallbacks: NotificationCallback[] = [];
  private threatAlertCallbacks: ((threat: ThreatData) => void)[] = [];
  private notificationQueue: NotificationOptions[] = [];
  private isAlertsEnabled: boolean = true;
  
  constructor() {
    // Monitor threat alerts toggle
    securityConfigManager.subscribe((change) => {
      if (change.setting === 'threatAlerts') {
        this.isAlertsEnabled = change.newValue;
        console.log(`[NotificationService] Threat alerts ${this.isAlertsEnabled ? 'enabled' : 'disabled'}`);
        
        // If disabled, clear threat alert queue
        if (!this.isAlertsEnabled) {
          this.threatAlertCallbacks = [];
        }
      }
    });
    
    // Monitor weekly reports toggle
    securityConfigManager.subscribe((change) => {
      if (change.setting === 'weeklyReports') {
        console.log(`[NotificationService] Weekly reports ${change.newValue ? 'enabled' : 'disabled'}`);
        if (change.newValue) {
          this.enableWeeklyReports();
        } else {
          this.disableWeeklyReports();
        }
      }
    });
    
    // Monitor update notifications toggle
    securityConfigManager.subscribe((change) => {
      if (change.setting === 'updateNotifications') {
        console.log(`[NotificationService] Update notifications ${change.newValue ? 'enabled' : 'disabled'}`);
      }
    });
    
    this.isAlertsEnabled = securityConfigManager.getSetting('threatAlerts');
  }
  
  /**
   * Register callback for general notifications
   */
  onNotification(callback: NotificationCallback): () => void {
    this.notificationCallbacks.push(callback);
    
    return () => {
      this.notificationCallbacks = this.notificationCallbacks.filter(cb => cb !== callback);
    };
  }
  
  /**
   * Register callback for threat alerts specifically
   */
  onThreatAlert(callback: (threat: ThreatData) => void): () => void {
    this.threatAlertCallbacks.push(callback);
    
    return () => {
      this.threatAlertCallbacks = this.threatAlertCallbacks.filter(cb => cb !== callback);
    };
  }
  
  /**
   * Show threat notification (respects threatAlerts toggle)
   */
  showThreatAlert(threatData: ThreatData): void {
    // Only show if threat alerts are enabled
    if (!this.isAlertsEnabled) {
      console.debug('[NotificationService] Threat alerts disabled, skipping notification');
      return;
    }
    
    console.log('[NotificationService] Displaying threat alert for:', threatData.type);
    
    const severity = threatData.severity >= 8 ? 'error' : threatData.severity >= 5 ? 'warning' : 'info';
    
    const notification: NotificationOptions = {
      title: `${threatData.type} Detected`,
      message: `A ${severity} level threat has been detected on the website you're visiting.`,
      severity: severity,
      duration: 8000,
      action: {
        label: 'View Details',
        callback: () => {
          // Emit threat alert to subscribers
          this.threatAlertCallbacks.forEach(callback => {
            try {
              callback(threatData);
            } catch (error) {
              console.error('Error in threat alert callback:', error);
            }
          });
        }
      }
    };
    
    this.displayNotification(notification);
  }
  
  /**
   * Show general notification
   */
  showNotification(options: NotificationOptions): void {
    console.log('[NotificationService] Showing notification:', options.title);
    this.displayNotification(options);
  }
  
  /**
   * Show blocking notification
   */
  showBlockingAlert(url: string, threatType: string): void {
    if (!this.isAlertsEnabled) {
      console.debug('[NotificationService] Alerts disabled, skipping blocking notification');
      return;
    }
    
    this.displayNotification({
      title: 'Website Blocked',
      message: `Access to this website has been blocked due to: ${threatType}`,
      severity: 'error',
      duration: 10000
    });
  }
  
  /**
   * Show weekly report notification
   */
  showWeeklyReport(stats: Record<string, any>): void {
    const weeklyReportsEnabled = securityConfigManager.getSetting('weeklyReports');
    
    if (!weeklyReportsEnabled) {
      console.debug('[NotificationService] Weekly reports disabled');
      return;
    }
    
    this.displayNotification({
      title: 'Weekly Security Report',
      message: `Your security scan summary is ready. ${stats.threats_detected || 0} threats detected this week.`,
      severity: 'info',
      duration: 10000
    });
  }
  
  /**
   * Show update notification
   */
  showUpdateNotification(updateInfo: Record<string, any>): void {
    const updateNotifEnabled = securityConfigManager.getSetting('updateNotifications');
    
    if (!updateNotifEnabled) {
      console.debug('[NotificationService] Update notifications disabled');
      return;
    }
    
    this.displayNotification({
      title: updateInfo.title || 'Update Available',
      message: updateInfo.description || 'A new version of MalwareSnipper is available.',
      severity: 'info',
      duration: 15000,
      action: {
        label: 'Update Now',
        callback: () => {
          window.location.href = '/update';
        }
      }
    });
  }
  
  /**
   * Internal method to display notification
   */
  private displayNotification(notification: NotificationOptions): void {
    // Queue notification
    this.notificationQueue.push(notification);
    
    // Emit to all registered callbacks
    this.notificationCallbacks.forEach(callback => {
      try {
        callback(notification);
      } catch (error) {
        console.error('Error in notification callback:', error);
      }
    });
  }
  
  /**
   * Enable weekly reports scheduler
   */
  private enableWeeklyReports(): void {
    console.log('[NotificationService] Enabling weekly reports');
    // Schedule weekly report generation
    // This would typically integrate with backend scheduling
  }
  
  /**
   * Disable weekly reports scheduler
   */
  private disableWeeklyReports(): void {
    console.log('[NotificationService] Disabling weekly reports');
    // Cancel scheduled reports
  }
  
  /**
   * Get notification history
   */
  getNotificationHistory(): NotificationOptions[] {
    return [...this.notificationQueue];
  }
  
  /**
   * Clear notification history
   */
  clearHistory(): void {
    this.notificationQueue = [];
  }
}

// Export singleton instance
let notificationServiceInstance: NotificationService;

export function getNotificationService(): NotificationService {
  if (!notificationServiceInstance) {
    notificationServiceInstance = new NotificationService();
  }
  return notificationServiceInstance;
}

export default NotificationService;
