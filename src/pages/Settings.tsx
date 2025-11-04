import { Settings as SettingsIcon, Shield, Bell, Database, Key } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

const Settings = () => {
  return (
    <DashboardLayout>
      <div className="p-6 max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <SettingsIcon className="w-10 h-10 text-primary" />
            <h1 className="text-4xl font-orbitron font-bold">Settings</h1>
          </div>
          <p className="text-muted-foreground">Configure your MalwareSnipper preferences</p>
        </div>

        {/* Settings Sections */}
        <div className="space-y-6">
          {/* Security Settings */}
          <div className="p-6 rounded-lg bg-card border border-primary/20 space-y-6">
            <div className="flex items-center gap-3">
              <Shield className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-orbitron font-bold">Security</h2>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="auto-scan" className="text-base">
                    Automatic Scanning
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically scan every website you visit
                  </p>
                </div>
                <Switch id="auto-scan" defaultChecked />
              </div>

              <Separator className="bg-primary/10" />

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="block-threats" className="text-base">
                    Block Malicious Sites
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically block access to detected threats
                  </p>
                </div>
                <Switch id="block-threats" defaultChecked />
              </div>

              <Separator className="bg-primary/10" />

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="strict-mode" className="text-base">
                    Strict Mode
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Flag suspicious websites with lower threshold
                  </p>
                </div>
                <Switch id="strict-mode" />
              </div>
            </div>
          </div>

          {/* Notification Settings */}
          <div className="p-6 rounded-lg bg-card border border-primary/20 space-y-6">
            <div className="flex items-center gap-3">
              <Bell className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-orbitron font-bold">Notifications</h2>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="threat-alerts" className="text-base">
                    Threat Alerts
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Get notified when threats are detected
                  </p>
                </div>
                <Switch id="threat-alerts" defaultChecked />
              </div>

              <Separator className="bg-primary/10" />

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="weekly-reports" className="text-base">
                    Weekly Reports
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Receive weekly security summary emails
                  </p>
                </div>
                <Switch id="weekly-reports" defaultChecked />
              </div>

              <Separator className="bg-primary/10" />

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="update-notifications" className="text-base">
                    Update Notifications
                  </Label>
                  <p className="text-sm text-muted-foreground">
                    Notify about new features and updates
                  </p>
                </div>
                <Switch id="update-notifications" />
              </div>
            </div>
          </div>

          {/* System Information */}
          <div className="p-6 rounded-lg bg-card border border-primary/20 space-y-6">
            <div className="flex items-center gap-3">
              <Database className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-orbitron font-bold">System Information</h2>
            </div>

            <div className="space-y-3 text-sm">
              <div className="flex justify-between py-2">
                <span className="text-muted-foreground">AI Model Version</span>
                <span className="font-mono">v2.3.1</span>
              </div>
              <Separator className="bg-primary/10" />
              <div className="flex justify-between py-2">
                <span className="text-muted-foreground">Last Database Update</span>
                <span>2025-11-04 12:00 UTC</span>
              </div>
              <Separator className="bg-primary/10" />
              <div className="flex justify-between py-2">
                <span className="text-muted-foreground">Extension Version</span>
                <span className="font-mono">1.5.2</span>
              </div>
              <Separator className="bg-primary/10" />
              <div className="flex justify-between py-2">
                <span className="text-muted-foreground">Detection Database Size</span>
                <span>2.3 GB</span>
              </div>
            </div>

            <Button variant="outline" className="w-full">
              Check for Updates
            </Button>
          </div>

          {/* API Settings */}
          <div className="p-6 rounded-lg bg-card border border-primary/20 space-y-6">
            <div className="flex items-center gap-3">
              <Key className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-orbitron font-bold">API Access</h2>
            </div>

            <p className="text-sm text-muted-foreground">
              API keys allow you to integrate MalwareSnipper detection into your own applications.
            </p>

            <div className="flex gap-3">
              <Button variant="default">Generate API Key</Button>
              <Button variant="outline">View Documentation</Button>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Settings;
