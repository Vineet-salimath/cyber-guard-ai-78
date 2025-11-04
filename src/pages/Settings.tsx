import { Settings as SettingsIcon, Shield, Bell, Database, Key } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

const Settings = () => {
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
                <Switch id="auto-scan" defaultChecked />
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
                <Switch id="block-threats" defaultChecked />
              </div>

              <Separator />

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="strict-mode" className="text-sm font-medium">
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
                <Switch id="threat-alerts" defaultChecked />
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
                <Switch id="weekly-reports" defaultChecked />
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
                <Switch id="update-notifications" />
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
