/**
 * Enterprise-Grade Security Configuration Manager
 * Singleton pattern with real-time toggle management
 */

export interface SecuritySettings {
  automaticScanning: boolean;
  blockMalicious: boolean;
  threatAlerts: boolean;
  weeklyReports: boolean;
  updateNotifications: boolean;
}

export interface SettingChange {
  setting: keyof SecuritySettings;
  oldValue: boolean;
  newValue: boolean;
  timestamp: number;
}

type SettingObserver = (change: SettingChange) => void;

class SecurityConfigurationManager {
  private static instance: SecurityConfigurationManager;
  
  private settings: SecuritySettings = {
    automaticScanning: true,
    blockMalicious: true,
    threatAlerts: true,
    weeklyReports: true,
    updateNotifications: false
  };
  
  private observers: SettingObserver[] = [];
  private settingsHistory: SettingChange[] = [];
  private isInitialized: boolean = false;
  private readonly STORAGE_KEY = 'malwareSnipper_securitySettings';
  
  private constructor() {
    this.loadSettings();
  }
  
  /**
   * Get singleton instance
   */
  static getInstance(): SecurityConfigurationManager {
    if (!SecurityConfigurationManager.instance) {
      SecurityConfigurationManager.instance = new SecurityConfigurationManager();
    }
    return SecurityConfigurationManager.instance;
  }
  
  /**
   * Subscribe to setting changes
   */
  subscribe(callback: SettingObserver): () => void {
    this.observers.push(callback);
    
    // Return unsubscribe function
    return () => {
      this.observers = this.observers.filter(obs => obs !== callback);
    };
  }
  
  /**
   * Notify all observers of setting change
   */
  private notifyObservers(change: SettingChange): void {
    console.log(`[SecurityConfig] Setting changed: ${change.setting} = ${change.newValue}`);
    this.observers.forEach(observer => {
      try {
        observer(change);
      } catch (error) {
        console.error('Error in observer callback:', error);
      }
    });
  }
  
  /**
   * Update a setting with validation and notification
   */
  updateSetting<K extends keyof SecuritySettings>(
    key: K,
    value: SecuritySettings[K]
  ): boolean {
    // Validate setting key exists
    if (!(key in this.settings)) {
      console.error(`Invalid setting key: ${key}`);
      return false;
    }
    
    const oldValue = this.settings[key];
    
    // Skip if value hasn't changed
    if (oldValue === value) {
      return true;
    }
    
    try {
      // Update local state
      this.settings[key] = value;
      
      // Log change
      const change: SettingChange = {
        setting: key,
        oldValue: oldValue as boolean,
        newValue: value as boolean,
        timestamp: Date.now()
      };
      
      this.settingsHistory.push(change);
      
      // Persist to storage
      this.persistSettings();
      
      // Notify all observers
      this.notifyObservers(change);
      
      return true;
    } catch (error) {
      console.error('Failed to update setting:', error);
      return false;
    }
  }
  
  /**
   * Get current setting value
   */
  getSetting<K extends keyof SecuritySettings>(key: K): SecuritySettings[K] {
    return this.settings[key];
  }
  
  /**
   * Get all settings
   */
  getAllSettings(): Readonly<SecuritySettings> {
    return Object.freeze({ ...this.settings });
  }
  
  /**
   * Load settings from storage
   */
  private loadSettings(): void {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        Object.assign(this.settings, parsed);
        console.log('[SecurityConfig] Settings loaded from storage');
      }
      this.isInitialized = true;
    } catch (error) {
      console.error('Failed to load settings:', error);
      this.isInitialized = true;
    }
  }
  
  /**
   * Persist settings to storage
   */
  private persistSettings(): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.settings));
    } catch (error) {
      console.error('Failed to persist settings:', error);
    }
  }
  
  /**
   * Reset to default settings
   */
  resetToDefaults(): void {
    this.settings = {
      automaticScanning: true,
      blockMalicious: true,
      threatAlerts: true,
      weeklyReports: true,
      updateNotifications: false
    };
    this.persistSettings();
    console.log('[SecurityConfig] Reset to default settings');
  }
  
  /**
   * Get settings history
   */
  getHistory(): SettingChange[] {
    return [...this.settingsHistory];
  }
  
  /**
   * Clear history
   */
  clearHistory(): void {
    this.settingsHistory = [];
  }
}

// Export singleton instance
export const securityConfigManager = SecurityConfigurationManager.getInstance();
export default SecurityConfigurationManager;
