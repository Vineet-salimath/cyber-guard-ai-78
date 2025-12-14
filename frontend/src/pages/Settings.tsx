import { Settings as SettingsIcon, Shield, Bell, Database, Key } from "lucide-react";
import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

const Settings = () => {
  const [settings, setSettings] = useState({
    autoScan: true,
    blockThreats: true,
    threatAlerts: true,
    weeklyReports: true,
    updateNotifications: false,
  });

  // Load settings from Chrome storage on mount
  useEffect(() => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['settings'], (result) => {
        if (result.settings) {
          setSettings(result.settings);
        }
      });
    }
  }, []);

  const handleToggle = (key: keyof typeof settings) => {
    setSettings(prev => {
      const updated = { ...prev, [key]: !prev[key] };
      
      // Persist to Chrome storage
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ settings: updated });
      }

      // Handle specific functionality for autoScan
      if (key === 'autoScan') {
        if (updated.autoScan) {
          // Start scanning
          sendMessageToExtension({
            type: 'ENABLE_SCANNING',
            payload: { autoScan: true }
          });
        } else {
          // Stop scanning
          sendMessageToExtension({
            type: 'DISABLE_SCANNING',
            payload: { autoScan: false }
          });
        }
      }

      // Handle block threats functionality
      if (key === 'blockThreats') {
        sendMessageToExtension({
          type: 'UPDATE_THREAT_BLOCKING',
          payload: { blockThreats: updated.blockThreats }
        });
      }

      // Handle threat alerts
      if (key === 'threatAlerts') {
        sendMessageToExtension({
          type: 'UPDATE_THREAT_ALERTS',
          payload: { threatAlerts: updated.threatAlerts }
        });
      }

      return updated;
    });
  };

  const sendMessageToExtension = (message: any) => {
    // Try to send message to extension via Chrome API
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          console.log('Extension message sent:', message);
        } else {
          console.log('Extension response:', response);
        }
      });
    }
    
    // Also send to backend API for settings sync
    fetch('http://localhost:5000/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    }).catch(err => console.log('Settings sync:', err));
  };

  return (
    <DashboardLayout>
      <div className="p-6 lg:p-8 max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <SettingsIcon className="w-8 h-8 text-primary" />
            <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
          </div>
          <p className="text-muted-foreground">Configure your MalwareSnipper preferences</p>
        </div>

        {/* Settings Sections */}
        <div className="space-y-6">
          {/* Security Settings */}
          <div className="p-6 rounded-xl bg-card border space-y-6">
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5 text-primary" />
              <h2 className="text-xl font-semibold">Security</h2>
            </div>

            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="auto-scan" className="text-sm font-medium">
                    Automatic Scanning
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically scan every website you visit
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <div className={`px-2 py-0.5 rounded text-xs font-bold ${
                    settings.autoScan 
                      ? 'bg-green-100 text-green-700' 
                      : 'bg-red-100 text-red-700'
                  }`}>
                    {settings.autoScan ? 'ON' : 'OFF'}
                  </div>
                  <Switch 
                    id="auto-scan" 
                    checked={settings.autoScan}
                    onCheckedChange={() => handleToggle('autoScan')}
                  />
                </div>
              </div>

              <Separator />

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="block-threats" className="text-sm font-medium">
                    Block Malicious Sites
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically block access to detected threats
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <div className={`px-2 py-0.5 rounded text-xs font-bold ${
                    settings.blockThreats 
                      ? 'bg-green-100 text-green-700' 
                      : 'bg-red-100 text-red-700'
                  }`}>
                    {settings.blockThreats ? 'ON' : 'OFF'}
                  </div>
                  <Switch 
                    id="block-threats" 
                    checked={settings.blockThreats}
                    onCheckedChange={() => handleToggle('blockThreats')}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Notification Settings */}
          <div className="p-6 rounded-xl bg-card border space-y-6">
            <div className="flex items-center gap-3">
              <Bell className="w-5 h-5 text-primary" />
              <h2 className="text-xl font-semibold">Notifications</h2>
            </div>

            <div className="space-y-5">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="threat-alerts" className="text-sm font-medium">
                    Threat Alerts
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Get notified when threats are detected
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <div className={`px-2 py-0.5 rounded text-xs font-bold ${
                    settings.threatAlerts 
                      ? 'bg-green-100 text-green-700' 
                      : 'bg-red-100 text-red-700'
                  }`}>
                    {settings.threatAlerts ? 'ON' : 'OFF'}
                  </div>
                  <Switch 
                    id="threat-alerts" 
                    checked={settings.threatAlerts}
                    onCheckedChange={() => handleToggle('threatAlerts')}
                  />
                </div>
              </div>

              <Separator />

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="weekly-reports" className="text-sm font-medium">
                    Weekly Reports
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Receive weekly security summary emails
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <div className={`px-2 py-0.5 rounded text-xs font-bold ${
                    settings.weeklyReports 
                      ? 'bg-green-100 text-green-700' 
                      : 'bg-red-100 text-red-700'
                  }`}>
                    {settings.weeklyReports ? 'ON' : 'OFF'}
                  </div>
                  <Switch 
                    id="weekly-reports" 
                    checked={settings.weeklyReports}
                    onCheckedChange={() => handleToggle('weeklyReports')}
                  />
                </div>
              </div>

              <Separator />

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="update-notifications" className="text-sm font-medium">
                    Update Notifications
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Notify about new features and updates
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <div className={`px-2 py-0.5 rounded text-xs font-bold ${
                    settings.updateNotifications 
                      ? 'bg-green-100 text-green-700' 
                      : 'bg-red-100 text-red-700'
                  }`}>
                    {settings.updateNotifications ? 'ON' : 'OFF'}
                  </div>
                  <Switch 
                    id="update-notifications" 
                    checked={settings.updateNotifications}
                    onCheckedChange={() => handleToggle('updateNotifications')}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* System Information */}
          <div className="p-6 rounded-xl bg-card border space-y-6">
            <div className="flex items-center gap-3">
              <Database className="w-5 h-5 text-primary" />
              <h2 className="text-xl font-semibold">System Information</h2>
            </div>

            <div className="space-y-3 text-sm">
              <div className="flex justify-between py-2">
                <span className="text-muted-foreground">AI Model Version</span>
                <span className="font-mono tabular-nums">v2.3.1</span>
              </div>
              <Separator />
              <div className="flex justify-between py-2">
                <span className="text-muted-foreground">Last Database Update</span>
                <span className="tabular-nums">2025-11-04 12:00 UTC</span>
              </div>
              <Separator />
              <div className="flex justify-between py-2">
                <span className="text-muted-foreground">Extension Version</span>
                <span className="font-mono tabular-nums">1.5.2</span>
              </div>
              <Separator />
              <div className="flex justify-between py-2">
                <span className="text-muted-foreground">Database Size</span>
                <span className="tabular-nums">2.3 GB</span>
              </div>
            </div>

            <Button variant="outline" className="w-full">
              Check for Updates
            </Button>
          </div>

          {/* API Settings */}
          <div className="p-6 rounded-xl bg-card border space-y-6">
            <div className="flex items-center gap-3">
              <Key className="w-5 h-5 text-primary" />
              <h2 className="text-xl font-semibold">API Access</h2>
            </div>

            <p className="text-sm text-muted-foreground">
              API keys allow you to integrate MalwareSnipper detection into your own applications.
            </p>

            <div className="flex gap-3">
              <Button>Generate API Key</Button>
              <Button variant="outline">Documentation</Button>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Settings;
