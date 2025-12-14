// SIEM-Style Live Threat Log Viewer Component
// Shows real-time scan results like a SIEM system (newest first, color-coded)

import { useEffect, useState, useRef } from "react";
import { Shield, AlertTriangle, AlertCircle, Clock, Globe, Activity } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface ThreatLog {
  id: string;
  timestamp: number;
  url: string;
  threatLevel: "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "SCANNING";
  riskScore: number;
  detectedBy?: number;
  scanId?: string;
}

export function SIEMLiveLogViewer() {
  const [logs, setLogs] = useState<ThreatLog[]>([]);
  const [isLive, setIsLive] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    console.log("🎯 [SIEM] Initializing live threat log viewer...");

    // Listen for extension messages via window.postMessage
    const handleMessage = (event: MessageEvent) => {
      // Security: Only accept messages from extension
      if (event.data?.source !== 'malware-snipper-extension') {
        return;
      }

      const { type, data } = event.data;
      console.log(`📊 [SIEM LOG] Received ${type}:`, data);

      switch (type) {
        case 'NEW_SCAN_RESULT':
          addLogEntry(data);
          break;
        case 'SCAN_STARTED':
          addScanningEntry(data);
          break;
        case 'DASHBOARD_READY':
          setIsLive(true);
          console.log("✅ [SIEM] Live connection established");
          break;
      }
    };

    window.addEventListener('message', handleMessage);

    // Load existing scans from extension storage
    loadExistingScans();

    return () => {
      window.removeEventListener('message', handleMessage);
    };
  }, []);

  // Auto-scroll to top when new logs arrive
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const loadExistingScans = () => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['autoScanHistory'], (result) => {
        const history = result.autoScanHistory || [];
        console.log(`📚 [SIEM] Loading ${history.length} existing scans from extension`);

        const logEntries: ThreatLog[] = history.map((scan: any) => ({
          id: `${scan.url}-${scan.timestamp}`,
          timestamp: scan.timestamp,
          url: scan.url,
          threatLevel: scan.threatLevel || 'SAFE',
          riskScore: scan.riskScore || 0,
          detectedBy: scan.stats?.malicious || 0,
          scanId: scan.scanId
        }));

        // Newest first (SIEM style)
        logEntries.sort((a, b) => b.timestamp - a.timestamp);
        setLogs(logEntries);
        setIsLive(true);
      });
    }
  };

  const addLogEntry = (scanData: any) => {
    const newLog: ThreatLog = {
      id: `${scanData.url}-${Date.now()}`,
      timestamp: Date.now(),
      url: scanData.url,
      threatLevel: scanData.threat_level || scanData.threatLevel || 'SAFE',
      riskScore: scanData.overall_risk_score || scanData.riskScore || 0,
      detectedBy: scanData.stats?.malicious || 0,
      scanId: scanData.scanId
    };

    console.log(`➕ [SIEM LOG] Adding new entry: ${newLog.url} [${newLog.threatLevel}]`);

    // Add to top (newest first)
    setLogs(prevLogs => {
      const updated = [newLog, ...prevLogs];
      // Keep last 100 entries
      return updated.slice(0, 100);
    });

    // Play alert sound for threats
    if (newLog.threatLevel === 'MALICIOUS') {
      playAlertSound();
    }
  };

  const addScanningEntry = (data: any) => {
    const scanningLog: ThreatLog = {
      id: `scanning-${Date.now()}`,
      timestamp: Date.now(),
      url: data.url,
      threatLevel: 'SCANNING',
      riskScore: 0
    };

    // Temporarily add scanning entry (will be replaced when scan completes)
    setLogs(prevLogs => [scanningLog, ...prevLogs]);

    // Remove scanning entry after scan completes (timeout fallback)
    setTimeout(() => {
      setLogs(prevLogs => prevLogs.filter(log => log.id !== scanningLog.id));
    }, 10000);
  };

  const playAlertSound = () => {
    try {
      const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTcIGWi77eefTRAMUKfj8LZjHAY4ktfzxXksB==');
      audio.volume = 0.3;
      audio.play().catch(() => {});
    } catch (error) {
      // Silently fail if audio not supported
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'SAFE':
        return <Shield className="h-4 w-4 text-green-500" />;
      case 'SUSPICIOUS':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case 'MALICIOUS':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      case 'SCANNING':
        return <Activity className="h-4 w-4 text-blue-500 animate-pulse" />;
      default:
        return <Globe className="h-4 w-4 text-gray-500" />;
    }
  };

  const getThreatBadge = (level: string) => {
    const variants: Record<string, any> = {
      SAFE: { variant: "outline", className: "bg-green-50 text-green-700 border-green-200" },
      SUSPICIOUS: { variant: "outline", className: "bg-yellow-50 text-yellow-700 border-yellow-200" },
      MALICIOUS: { variant: "destructive", className: "bg-red-50 text-red-700 border-red-200" },
      SCANNING: { variant: "outline", className: "bg-blue-50 text-blue-700 border-blue-200 animate-pulse" }
    };
    return variants[level] || variants.SAFE;
  };

  const formatTimestamp = (timestamp: number) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();

    // Show relative time for recent logs
    if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;

    // Show absolute time for older logs
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    });
  };

  const formatUrl = (url: string) => {
    try {
      const urlObj = new URL(url);
      return {
        domain: urlObj.hostname,
        path: urlObj.pathname + urlObj.search
      };
    } catch {
      return { domain: url, path: '' };
    }
  };

  return (
    <div className="space-y-4">
      {/* Header with Live Status */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className={`h-5 w-5 ${isLive ? 'text-green-500 animate-pulse' : 'text-gray-400'}`} />
          <div>
            <h3 className="text-lg font-semibold">Live Threat Log</h3>
            <p className="text-sm text-muted-foreground">
              Real-time SIEM-style monitoring • {logs.length} entries
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant={isLive ? "default" : "secondary"} className="gap-2">
            <div className={`h-2 w-2 rounded-full ${isLive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
            {isLive ? 'LIVE' : 'OFFLINE'}
          </Badge>

          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-3 py-1 text-xs rounded-md ${
              autoScroll ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'
            }`}
          >
            {autoScroll ? '🔄 Auto-scroll' : '⏸️ Manual'}
          </button>
        </div>
      </div>

      {/* Log Table */}
      <div className="border rounded-lg bg-card">
        <ScrollArea className="h-[600px]" ref={scrollRef}>
          <Table>
            <TableHeader className="sticky top-0 bg-muted/50 backdrop-blur">
              <TableRow>
                <TableHead className="w-[100px]"><Clock className="h-4 w-4 inline mr-2" />Time</TableHead>
                <TableHead className="w-[120px]">Status</TableHead>
                <TableHead><Globe className="h-4 w-4 inline mr-2" />URL</TableHead>
                <TableHead className="w-[100px] text-right">Risk Score</TableHead>
                <TableHead className="w-[100px] text-right">Detected By</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-12 text-muted-foreground">
                    <Activity className="h-12 w-12 mx-auto mb-3 opacity-20" />
                    <p>No scans yet. Visit a website to see real-time threat logs.</p>
                  </TableCell>
                </TableRow>
              ) : (
                logs.map((log) => {
                  const { domain, path } = formatUrl(log.url);
                  const badgeProps = getThreatBadge(log.threatLevel);

                  return (
                    <TableRow
                      key={log.id}
                      className={`hover:bg-muted/50 transition-colors ${
                        log.threatLevel === 'MALICIOUS' ? 'bg-red-50/30' :
                        log.threatLevel === 'SUSPICIOUS' ? 'bg-yellow-50/30' :
                        log.threatLevel === 'SCANNING' ? 'bg-blue-50/30' : ''
                      }`}
                    >
                      <TableCell className="font-mono text-xs">
                        {formatTimestamp(log.timestamp)}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {getThreatIcon(log.threatLevel)}
                          <Badge {...badgeProps}>
                            {log.threatLevel}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        <div className="max-w-md truncate">
                          <span className="font-semibold">{domain}</span>
                          <span className="text-muted-foreground">{path}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right font-mono">
                        {log.threatLevel === 'SCANNING' ? (
                          <span className="text-muted-foreground">--</span>
                        ) : (
                          <span className={
                            log.riskScore >= 60 ? 'text-red-600 font-bold' :
                            log.riskScore >= 30 ? 'text-yellow-600' :
                            'text-green-600'
                          }>
                            {log.riskScore}%
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-right font-mono text-sm">
                        {log.detectedBy !== undefined ? (
                          <span className={log.detectedBy > 0 ? 'text-red-600 font-semibold' : 'text-muted-foreground'}>
                            {log.detectedBy}/70+
                          </span>
                        ) : (
                          <span className="text-muted-foreground">--</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </ScrollArea>
      </div>
    </div>
  );
}
