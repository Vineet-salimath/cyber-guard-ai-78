import { useState } from "react";
import { Shield, AlertTriangle, Activity, Users } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import StatCard from "@/components/StatCard";
import ScanTable from "@/components/ScanTable";
import ThreatCharts from "@/components/ThreatCharts";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";

interface Scan {
  id: string;
  url: string;
  timestamp: string;
  status: "safe" | "suspicious" | "malicious";
  threatScore: number;
}

const Dashboard = () => {
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);

  const mockScans: Scan[] = [
    { id: "1", url: "https://safe-site.com", timestamp: "2025-11-04 14:32:15", status: "safe", threatScore: 5 },
    { id: "2", url: "https://suspicious-link.net", timestamp: "2025-11-04 14:28:42", status: "suspicious", threatScore: 65 },
    { id: "3", url: "https://malware-detected.org", timestamp: "2025-11-04 14:15:03", status: "malicious", threatScore: 92 },
    { id: "4", url: "https://trusted-bank.com", timestamp: "2025-11-04 14:10:21", status: "safe", threatScore: 2 },
    { id: "5", url: "https://phishing-attempt.biz", timestamp: "2025-11-04 14:05:18", status: "malicious", threatScore: 88 },
  ];

  return (
    <DashboardLayout>
      <div className="p-6 lg:p-8 space-y-8 max-w-7xl mx-auto">
        {/* Header */}
        <div className="space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">Real-time threat monitoring and analytics</p>
        </div>

        {/* Stats Grid */}
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          <StatCard
            title="Total Scans"
            value="1,000"
            icon={Activity}
            trend="+12% from last week"
            variant="default"
          />
          <StatCard
            title="Active Alerts"
            value="34"
            icon={AlertTriangle}
            trend="3 new today"
            variant="danger"
          />
          <StatCard
            title="Detection Rate"
            value="99.8%"
            icon={Shield}
            trend="+0.2% improved"
            variant="success"
          />
          <StatCard
            title="Protected Users"
            value="2,547"
            icon={Users}
            trend="+156 this month"
            variant="default"
          />
        </div>

        {/* Charts */}
        <ThreatCharts />

        {/* Scan Table */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">Recent Scans</h2>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
              <span>Live</span>
            </div>
          </div>
          <ScanTable scans={mockScans} onViewDetails={setSelectedScan} />
        </div>
      </div>

      {/* Details Modal */}
      <Dialog open={!!selectedScan} onOpenChange={() => setSelectedScan(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="text-2xl">Threat Report</DialogTitle>
            <DialogDescription>Detailed analysis of the scanned website</DialogDescription>
          </DialogHeader>
          {selectedScan && (
            <div className="space-y-6">
              {/* Status */}
              <div className="flex items-center gap-4">
                <Badge
                  variant="outline"
                  className={
                    selectedScan.status === "safe"
                      ? "bg-success/10 text-success border-success/20"
                      : selectedScan.status === "suspicious"
                      ? "bg-warning/10 text-warning border-warning/20"
                      : "bg-destructive/10 text-destructive border-destructive/20"
                  }
                >
                  {selectedScan.status.toUpperCase()}
                </Badge>
                <span className="text-2xl font-bold">{selectedScan.threatScore}%</span>
              </div>

              {/* URL */}
              <div className="space-y-2">
                <h3 className="font-semibold text-sm text-muted-foreground">Website URL</h3>
                <p className="font-mono text-sm bg-secondary p-3 rounded-lg break-all border">
                  {selectedScan.url}
                </p>
              </div>

              {/* Details Grid */}
              <div className="grid md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <h3 className="font-semibold text-sm text-muted-foreground">Scan Time</h3>
                  <p className="text-sm">{selectedScan.timestamp}</p>
                </div>
                <div className="space-y-2">
                  <h3 className="font-semibold text-sm text-muted-foreground">AI Model</h3>
                  <p className="text-sm">MalwareSnipper v2.3.1</p>
                </div>
              </div>

              {/* Risk Summary */}
              <div className="space-y-2">
                <h3 className="font-semibold text-sm text-muted-foreground">Risk Summary</h3>
                <div className="p-4 rounded-lg bg-secondary border text-sm leading-relaxed">
                  {selectedScan.status === "safe" && (
                    <p>This website passed all security checks. No malicious content or suspicious patterns detected.</p>
                  )}
                  {selectedScan.status === "suspicious" && (
                    <p>
                      This website exhibits suspicious behavior. Proceed with caution. Potential indicators include unusual
                      scripts, redirects, or obfuscated code.
                    </p>
                  )}
                  {selectedScan.status === "malicious" && (
                    <p className="text-destructive font-medium">
                      ⚠️ DANGER: This website contains confirmed malware or phishing content. Do not proceed or enter any personal information.
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  );
};

export default Dashboard;
