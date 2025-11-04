import { useState } from "react";
import { Shield, Brain, AlertTriangle, ExternalLink } from "lucide-react";
import { motion } from "framer-motion";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

const Extension = () => {
  const [scanStatus, setScanStatus] = useState<"safe" | "suspicious" | "malicious">("safe");
  const [isScanning, setIsScanning] = useState(false);

  const handleScan = (status: "safe" | "suspicious" | "malicious") => {
    setIsScanning(true);
    setTimeout(() => {
      setScanStatus(status);
      setIsScanning(false);
    }, 2000);
  };

  const getStatusColor = () => {
    switch (scanStatus) {
      case "safe":
        return "text-success";
      case "suspicious":
        return "text-warning";
      case "malicious":
        return "text-destructive";
    }
  };

  const getThreatScore = () => {
    switch (scanStatus) {
      case "safe":
        return 5;
      case "suspicious":
        return 65;
      case "malicious":
        return 92;
    }
  };

  return (
    <DashboardLayout>
      <div className="p-6 max-w-6xl mx-auto space-y-8">
        {/* Header */}
        <div className="space-y-2">
          <h1 className="text-4xl font-orbitron font-bold">Chrome Extension Demo</h1>
          <p className="text-muted-foreground">Interactive preview of the MalwareSnipper browser extension</p>
        </div>

        {/* Demo Controls */}
        <div className="flex gap-4 p-4 bg-card rounded-lg border border-primary/20">
          <div className="text-sm text-muted-foreground flex items-center gap-2">
            Simulate scan result:
          </div>
          <Button variant="success" size="sm" onClick={() => handleScan("safe")}>
            Safe Site
          </Button>
          <Button variant="warning" size="sm" onClick={() => handleScan("suspicious")}>
            Suspicious
          </Button>
          <Button variant="destructive" size="sm" onClick={() => handleScan("malicious")}>
            Malicious
          </Button>
        </div>

        {/* Extension Popup Preview */}
        <div className="flex justify-center">
          <div className="w-[350px] h-[500px] bg-card border-2 border-primary/30 rounded-lg shadow-[0_0_50px_hsl(180_100%_50%_/_0.2)] overflow-hidden">
            {/* Extension Header */}
            <div className="bg-secondary p-4 border-b border-primary/20">
              <div className="flex items-center gap-2">
                <Shield className="w-6 h-6 text-primary" />
                <span className="font-orbitron font-bold text-lg text-gradient">MalwareSnipper</span>
              </div>
            </div>

            {/* Scan Status Card */}
            <div className="p-6 space-y-6">
              {/* Radar Animation */}
              <div className="relative flex items-center justify-center">
                <div className="relative w-40 h-40">
                  {/* Outer rings */}
                  <div className={`absolute inset-0 rounded-full border-2 ${getStatusColor()} opacity-20`} />
                  <div className={`absolute inset-4 rounded-full border-2 ${getStatusColor()} opacity-30`} />
                  <div className={`absolute inset-8 rounded-full border-2 ${getStatusColor()} opacity-40`} />

                  {/* Radar sweep */}
                  {isScanning && (
                    <motion.div
                      className="absolute inset-0"
                      animate={{ rotate: 360 }}
                      transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                    >
                      <div
                        className={`absolute top-1/2 left-1/2 w-1/2 h-0.5 origin-left ${
                          scanStatus === "safe"
                            ? "bg-success"
                            : scanStatus === "suspicious"
                            ? "bg-warning"
                            : "bg-destructive"
                        } opacity-60`}
                      />
                    </motion.div>
                  )}

                  {/* Center icon */}
                  <div className="absolute inset-0 flex items-center justify-center">
                    {isScanning ? (
                      <Brain className={`w-12 h-12 ${getStatusColor()} animate-pulse`} />
                    ) : scanStatus === "safe" ? (
                      <Shield className={`w-12 h-12 ${getStatusColor()}`} />
                    ) : (
                      <AlertTriangle className={`w-12 h-12 ${getStatusColor()}`} />
                    )}
                  </div>
                </div>
              </div>

              {/* Status Text */}
              <div className="text-center space-y-2">
                <Badge
                  variant="outline"
                  className={
                    scanStatus === "safe"
                      ? "bg-success/20 text-success border-success/30"
                      : scanStatus === "suspicious"
                      ? "bg-warning/20 text-warning border-warning/30"
                      : "bg-destructive/20 text-destructive border-destructive/30"
                  }
                >
                  {isScanning ? "SCANNING..." : scanStatus.toUpperCase()}
                </Badge>
                <p className="text-sm text-muted-foreground">Website Status</p>
              </div>

              {/* Threat Score Bar */}
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Threat Score</span>
                  <span className="font-mono font-bold">{getThreatScore()}%</span>
                </div>
                <div className="w-full h-3 bg-secondary rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${getThreatScore()}%` }}
                    transition={{ duration: 0.5 }}
                    className={`h-full ${
                      scanStatus === "safe"
                        ? "bg-success"
                        : scanStatus === "suspicious"
                        ? "bg-warning"
                        : "bg-destructive"
                    }`}
                  />
                </div>
              </div>

              {/* Details Section */}
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">URL</span>
                  <span className="font-mono">example.com</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Scan Time</span>
                  <span>0.4s</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">AI Model</span>
                  <span>v2.3.1</span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="space-y-2">
                <Button variant="default" className="w-full gap-2" size="sm">
                  <ExternalLink className="w-4 h-4" />
                  View Detailed Report
                </Button>
                <Button variant="outline" className="w-full" size="sm">
                  Report False Positive
                </Button>
              </div>

              {/* Footer */}
              <div className="text-center text-xs text-muted-foreground pt-2 border-t border-primary/20">
                Powered by MalwareSnipper AI
              </div>
            </div>
          </div>
        </div>

        {/* Features List */}
        <div className="grid md:grid-cols-2 gap-6 mt-8">
          <div className="p-6 rounded-lg bg-card border border-primary/20">
            <h3 className="font-orbitron font-bold text-xl mb-4">Extension Features</h3>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>✓ Real-time website scanning as you browse</li>
              <li>✓ Visual threat indicators with color-coded alerts</li>
              <li>✓ Instant threat score calculation</li>
              <li>✓ Detailed security reports with AI analysis</li>
              <li>✓ One-click access to dashboard</li>
              <li>✓ False positive reporting system</li>
            </ul>
          </div>

          <div className="p-6 rounded-lg bg-card border border-primary/20">
            <h3 className="font-orbitron font-bold text-xl mb-4">How It Works</h3>
            <ol className="space-y-2 text-sm text-muted-foreground list-decimal list-inside">
              <li>Navigate to any website in Chrome</li>
              <li>Extension automatically scans page content</li>
              <li>AI analyzes code, scripts, and behavior patterns</li>
              <li>Threat score calculated in under 1 second</li>
              <li>Visual feedback displayed in popup</li>
              <li>Full report available in main dashboard</li>
            </ol>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Extension;
