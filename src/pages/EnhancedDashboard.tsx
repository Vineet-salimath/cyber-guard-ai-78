// MALWARE SNIPPER - ENHANCED REAL-TIME DASHBOARD
// 5-Tab Structure with Live Updates via BroadcastChannel + WebSocket

import { useState, useEffect, useRef } from "react";
import { Shield, AlertTriangle, Activity, Radio, FileText, ExternalLink, AlertCircle } from "lucide-react";
import io from 'socket.io-client';
import DashboardLayout from "@/components/DashboardLayout";
import StatCard from "@/components/StatCard";
import ScanTable from "@/components/ScanTable";
import ThreatCharts from "@/components/ThreatCharts";
import RealtimePieChart from "@/components/RealtimePieChart";
import LiveThreatFeed from "@/components/LiveThreatFeed";
import { apiService } from "@/services/api";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { PulseDot, GlowingBadge, AnimatedGradientBackground } from "@/components/ui/glowing-badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface Vulnerability {
  id: string;
  severity: string;
  cvss_score: number;
  description: string;
  remediation: string;
}

interface Scan {
  id: string;
  url: string;
  timestamp: string;
  status: "safe" | "suspicious" | "malicious";
  threatScore: number;
  threatNames?: string[];
  vulnerabilities?: Vulnerability[];
  ml_prediction?: string;
  risk?: string;
  score?: number;
}

interface ScanStats {
  total_scans: number;
  benign_count: number;
  suspicious_count: number;
  malicious_count: number;
  benign_percentage: number;
  suspicious_percentage: number;
  malicious_percentage: number;
  last_updated: string;
}

interface RealtimeStats {
  totalScans: number;
  safeSites: number;
  suspiciousSites: number;
  maliciousSites: number;
  lastUpdated: number;
}

interface LiveScanEvent {
  type: string;
  data?: any;
  url?: string;
  timestamp: number;
}

const BACKEND_URL = 'http://localhost:5000';

const EnhancedDashboard = () => {
  // State management
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [realtimeStats, setRealtimeStats] = useState<RealtimeStats>({
    totalScans: 0,
    safeSites: 0,
    suspiciousSites: 0,
    maliciousSites: 0,
    lastUpdated: Date.now()
  });
  const [scanStats, setScanStats] = useState<ScanStats>({
    total_scans: 0,
    benign_count: 0,
    suspicious_count: 0,
    malicious_count: 0,
    benign_percentage: 0,
    suspicious_percentage: 0,
    malicious_percentage: 0,
    last_updated: new Date().toISOString()
  });
  const [liveFeed, setLiveFeed] = useState<LiveScanEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [dataSource, setDataSource] = useState<'extension' | 'backend' | 'none'>('none');
  const [isLoading, setIsLoading] = useState(true);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  
  const broadcastChannelRef = useRef<BroadcastChannel | null>(null);
  const socketRef = useRef<any>(null);

  // Initialize real-time connection
  useEffect(() => {
    console.log('🚀 [INIT] Initializing dashboard...');
    setIsLoading(true);
    
    try {
      initializeWebSocket();
      initializeExtensionListener(); // Listen for extension messages
      loadInitialStats(); // Load stats once at startup (no auto-refresh)
    } catch (error) {
      console.error('❌ [INIT] Initialization error:', error);
      setConnectionError(error instanceof Error ? error.message : 'Initialization failed');
    } finally {
      // Set loading to false after 2 seconds regardless of connection status
      setTimeout(() => {
        setIsLoading(false);
        console.log('✅ [INIT] Dashboard initialization complete');
      }, 2000);
    }

    return () => {
      cleanup();
    };
  }, []);

  // Initialize BroadcastChannel - REMOVED (not needed with chrome.runtime.sendMessage)
  
  // NEW: Listen for messages from extension via window.postMessage
  const initializeExtensionListener = () => {
    console.log('🔌 [EXTENSION] Setting up message listener...');
    
    // Listen for window.postMessage from extension (injected script)
    const handleMessage = (event: MessageEvent) => {
      // Security: Only accept messages from our own origin
      if (event.origin !== window.location.origin) {
        console.warn('⚠️ [EXTENSION] Rejected message from invalid origin:', event.origin);
        return;
      }
      
      const message = event.data;
      
      if (message && message.type === 'URL_VISITED' && message.url) {
        const url = message.url;
        
        // CRITICAL: Block dashboard URLs IMMEDIATELY - don't even log them
        if (url.includes('localhost:8082') || url.includes('127.0.0.1:8082')) {
          return; // Silent ignore - no logs
        }
        
        console.log('📨 [EXTENSION] Received URL:', url);
        console.log('🌐 [EXTENSION] URL visited from extension:', url);
        console.log('📤 [EXTENSION] Forwarding to backend for scanning...');
        
        // Forward to backend for scanning (SINGLE REQUEST)
        fetch(`${BACKEND_URL}/api/scan`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Origin': window.location.origin // Important for CORS
          },
          body: JSON.stringify({ 
            url: url,
            timestamp: message.timestamp || Date.now(),
            source: message.source || 'extension'
          })
        })
          .then(response => {
            if (response.ok) {
              return response.json();
            } else {
              throw new Error(`Backend returned ${response.status}`);
            }
          })
          .then(result => {
            console.log('✅ [BACKEND] Scan initiated:', result);
          })
          .catch(error => {
            console.error('❌ [BACKEND] Scan failed:', error);
          });
      }
    };
    
    window.addEventListener('message', handleMessage);
    console.log('✅ [EXTENSION] window.postMessage listener ready');
    
    return () => {
      window.removeEventListener('message', handleMessage);
      console.log('🔌 [EXTENSION] Message listener removed');
    };
  };

  // Load initial statistics (NO AUTO-REFRESH, ONE-TIME ONLY)
  const loadInitialStats = async () => {
    try {
      console.log('📊 [STATS] Loading initial scan statistics...');
      
      // Test connection first
      const isHealthy = await apiService.testConnection();
      if (!isHealthy) {
        setConnectionError('Cannot connect to backend. Please ensure it is running on http://localhost:5000');
        return;
      }

      const stats = await apiService.getScanStats();
      setScanStats(stats);
      setConnectionError(null);
      console.log('✅ [STATS] Loaded:', stats);
    } catch (error) {
      console.error('❌ [STATS] Error loading scan statistics:', error);
      setConnectionError(error instanceof Error ? error.message : 'Failed to load statistics');
    }
  };

  // Initialize WebSocket connection for real-time backend updates
  const initializeWebSocket = () => {
    console.log('🔌 [WEBSOCKET] Connecting to backend:', BACKEND_URL);
    const socket = io(BACKEND_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });
    socketRef.current = socket;

    socket.on('connect', () => {
      console.log('✅ [WEBSOCKET] Connected to backend successfully!');
      console.log('🆔 [WEBSOCKET] Socket ID:', socket.id);
      setIsConnected(true);
    });

    socket.on('disconnect', (reason) => {
      console.warn('❌ [WEBSOCKET] Disconnected. Reason:', reason);
      setIsConnected(false);
    });

    socket.on('connect_error', (error) => {
      console.error('❌ [WEBSOCKET] Connection error:', error.message);
      console.error('🔍 [WEBSOCKET] Is backend running on', BACKEND_URL, '?');
      setIsConnected(false);
    });

    socket.on('error', (error) => {
      console.error('❌ [WEBSOCKET] Socket error:', error);
    });

    // Listen for real-time scan updates from backend
    socket.on('new_scan', (data: any) => {
      console.log('🔥 [WEBSOCKET] Real-time scan received!');
      console.log('📦 [WEBSOCKET] Data:', JSON.stringify(data, null, 2));
      
      // Normalize threat level
      const risk = data.risk || data.threat_level || data.classification || 'benign';
      const threatLevel = risk.toUpperCase();
      let status: "safe" | "suspicious" | "malicious" = "safe";
      
      if (risk === 'malicious' || threatLevel === 'MALICIOUS' || threatLevel === 'RANSOMWARE') {
        status = 'malicious';
      } else if (risk === 'suspicious' || threatLevel === 'SUSPICIOUS' || threatLevel === 'PHISHING' || threatLevel === 'OBFUSCATED_JS') {
        status = 'suspicious';
      } else {
        status = 'safe';
      }

      console.log('🎯 [CLASSIFICATION] URL:', data.url, '| Status:', status, '| Risk:', risk);
      
      // Update scan stats manually (increment counters)
      setScanStats(prev => {
        const newStats = {
          total_scans: prev.total_scans + 1,
          benign_count: prev.benign_count + (status === 'safe' ? 1 : 0),
          suspicious_count: prev.suspicious_count + (status === 'suspicious' ? 1 : 0),
          malicious_count: prev.malicious_count + (status === 'malicious' ? 1 : 0),
          benign_percentage: 0,
          suspicious_percentage: 0,
          malicious_percentage: 0,
          last_updated: new Date().toISOString()
        };
        
        // Calculate percentages
        if (newStats.total_scans > 0) {
          newStats.benign_percentage = (newStats.benign_count / newStats.total_scans) * 100;
          newStats.suspicious_percentage = (newStats.suspicious_count / newStats.total_scans) * 100;
          newStats.malicious_percentage = (newStats.malicious_count / newStats.total_scans) * 100;
        }
        
        console.log('📊 [STATS] Updated scan stats:', newStats);
        return newStats;
      });

      // Create new scan entry
      const newScan: Scan = {
        id: String(data.id || data.url || Date.now()),
        url: data.url,
        timestamp: data.timestamp || new Date().toISOString(),
        status: status,
        threatScore: data.score || data.risk_score || data.overall_risk_score || 0,
        threatNames: data.threat_names || [],
        vulnerabilities: data.vulnerabilities || [],
        ml_prediction: data.ml_prediction,
        risk: risk,
        score: data.score || data.risk_score || 0
      };

      // Add to scans list (prepend to show newest first)
      setScans(prev => {
        const filtered = prev.filter(s => s.url !== newScan.url);
        const updated = [newScan, ...filtered].slice(0, 100);
        console.log('📋 [SCANS] Updated scan list. Total scans:', updated.length);
        return updated;
      });

      // Update stats
      setRealtimeStats(prev => {
        const updated = {
          totalScans: prev.totalScans + 1,
          safeSites: prev.safeSites + (status === 'safe' ? 1 : 0),
          suspiciousSites: prev.suspiciousSites + (status === 'suspicious' ? 1 : 0),
          maliciousSites: prev.maliciousSites + (status === 'malicious' ? 1 : 0),
          lastUpdated: Date.now()
        };
        console.log('📈 [STATS] Updated realtime stats:', updated);
        return updated;
      });

      console.log('✅ [WEBSOCKET] Scan processing complete!');
    });

    return socket;
  };

  // Cleanup
  const cleanup = () => {
    if (broadcastChannelRef.current) {
      broadcastChannelRef.current.close();
    }
    if (socketRef.current) {
      socketRef.current.disconnect();
    }
  };

  // Calculate detection rate
  const detectionRate = realtimeStats.totalScans > 0
    ? ((realtimeStats.safeSites / realtimeStats.totalScans) * 100).toFixed(1)
    : '0';

  // Loading state
  if (isLoading) {
    return (
      <DashboardLayout>
        <div className="min-h-screen flex items-center justify-center">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <Radio className="h-6 w-6 animate-pulse text-primary" />
                Initializing Dashboard...
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <div className="h-2 w-2 rounded-full bg-primary animate-pulse" />
                  Connecting to backend...
                </div>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <div className="h-2 w-2 rounded-full bg-primary animate-pulse" />
                  Setting up WebSocket...
                </div>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <div className="h-2 w-2 rounded-full bg-primary animate-pulse" />
                  Loading extension listener...
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                This should take just a moment...
              </p>
            </CardContent>
          </Card>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Connection Error Alert */}
        {connectionError && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              <strong>Connection Error:</strong> {connectionError}
              <br />
              <span className="text-xs">Make sure the backend is running on http://localhost:5000</span>
            </AlertDescription>
          </Alert>
        )}

        {/* Header with Connection Status */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">MalwareSnipper Dashboard</h1>
            <p className="text-muted-foreground">Real-time threat detection and analysis</p>
          </div>
          
          <div className="flex items-center gap-4">
            <Badge variant={isConnected ? "default" : "destructive"} className="gap-2">
              <Radio className={`h-3 w-3 ${isConnected ? 'animate-pulse' : ''}`} />
              {isConnected ? 'Live' : 'Disconnected'}
            </Badge>
          </div>
        </div>

        {/* 3-Tab Navigation */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="overview" className="gap-2">
              <Activity className="h-4 w-4" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="analysis" className="gap-2">
              <AlertTriangle className="h-4 w-4" />
              Threat Analysis
            </TabsTrigger>
            <TabsTrigger value="logs" className="gap-2">
              <FileText className="h-4 w-4" />
              Scan Logs
            </TabsTrigger>
          </TabsList>

          {/* TAB 1: Overview */}
          <TabsContent value="overview" className="space-y-6">
            {/* Stats Cards with Persistent Counters */}
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
              <StatCard
                title="Total Scans"
                value={scanStats.total_scans.toString()}
                icon={Shield}
                trend={isConnected ? "+Live" : "Offline"}
                variant="default"
              />
              <StatCard
                title="Benign Sites"
                value={scanStats.benign_count.toString()}
                icon={Shield}
                trend={`${scanStats.benign_percentage.toFixed(1)}%`}
                variant="success"
              />
              <StatCard
                title="Suspicious"
                value={scanStats.suspicious_count.toString()}
                icon={AlertTriangle}
                trend={`${scanStats.suspicious_percentage.toFixed(1)}%`}
                variant="warning"
              />
              <StatCard
                title="Malicious"
                value={scanStats.malicious_count.toString()}
                icon={AlertTriangle}
                trend={`${scanStats.malicious_percentage.toFixed(1)}%`}
                variant="danger"
              />
            </div>

            {/* Two-column layout for Pie Chart and Live Feed */}
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Real-time Pie Chart */}
              <RealtimePieChart stats={scanStats} />

              {/* Live Threat Feed */}
              <LiveThreatFeed scans={scans} maxItems={10} />
            </div>

            {/* Traditional Threat Charts */}
            <ThreatCharts />

            {/* Full Recent Scans Table */}
            <Card>
              <CardHeader>
                <CardTitle>All Recent Scans</CardTitle>
                <CardDescription>Complete scan history with details</CardDescription>
              </CardHeader>
              <CardContent>
                <ScanTable scans={scans.slice(0, 50)} onViewDetails={setSelectedScan} />
              </CardContent>
            </Card>
          </TabsContent>

          {/* TAB 2: Threat Analysis */}
          <TabsContent value="analysis" className="space-y-6">
            <ThreatCharts />
            
            <Card>
              <CardHeader>
                <CardTitle>Threat Breakdown</CardTitle>
                <CardDescription>Detailed analysis of detected threats</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {scans.filter(s => s.status !== 'safe').map((scan, index) => (
                    <div key={index} className="p-4 border rounded-lg">
                      <div className="flex items-start justify-between">
                        <div>
                          <h4 className="font-semibold">{scan.url}</h4>
                          <p className="text-sm text-muted-foreground">
                            Risk Score: {scan.threatScore.toFixed(1)}%
                          </p>
                          {scan.threatNames && scan.threatNames.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-2">
                              {scan.threatNames.slice(0, 5).map((threat, i) => (
                                <Badge key={i} variant="outline" className="text-xs">
                                  {threat}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </div>
                        <Badge variant={scan.status === 'suspicious' ? 'secondary' : 'destructive'}>
                          {scan.status?.toUpperCase()}
                        </Badge>
                      </div>
                    </div>
                  ))}
                  {scans.filter(s => s.status !== 'safe').length === 0 && (
                    <Alert>
                      <AlertDescription>
                        No threats detected in recent scans
                      </AlertDescription>
                    </Alert>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* TAB 3: Scan Logs */}
          <TabsContent value="logs" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Complete Scan History</CardTitle>
                <CardDescription>All scans from extension and API</CardDescription>
              </CardHeader>
              <CardContent>
                <ScanTable scans={scans} onViewDetails={setSelectedScan} />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* Scan Details Modal */}
      <Dialog open={!!selectedScan} onOpenChange={() => setSelectedScan(null)}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-2xl flex items-center gap-2">
              {selectedScan?.status === 'malicious' && <AlertCircle className="h-6 w-6 text-destructive" />}
              {selectedScan?.status === 'suspicious' && <AlertTriangle className="h-6 w-6 text-warning" />}
              {selectedScan?.status === 'safe' && <Shield className="h-6 w-6 text-success" />}
              Threat Analysis Report
            </DialogTitle>
            <DialogDescription>
              Detailed security analysis and vulnerability assessment
            </DialogDescription>
          </DialogHeader>

          {selectedScan && (
            <div className="space-y-6">
              {/* Status Badge */}
              <div className="flex items-center gap-4">
                <Badge
                  variant="outline"
                  className={
                    selectedScan.status === "safe"
                      ? "bg-success/10 text-success border-success/20 text-lg py-2 px-4"
                      : selectedScan.status === "suspicious"
                      ? "bg-warning/10 text-warning border-warning/20 text-lg py-2 px-4"
                      : "bg-destructive/10 text-destructive border-destructive/20 text-lg py-2 px-4"
                  }
                >
                  {selectedScan.status.toUpperCase()}
                </Badge>
                <div>
                  <div className="text-3xl font-bold">{selectedScan.threatScore}%</div>
                  <div className="text-sm text-muted-foreground">Risk Score</div>
                </div>
              </div>

              {/* URL */}
              <div className="space-y-2">
                <h3 className="font-semibold text-sm text-muted-foreground flex items-center gap-2">
                  <ExternalLink className="h-4 w-4" />
                  Website URL
                </h3>
                <p className="font-mono text-sm bg-secondary p-3 rounded-lg break-all border">
                  {selectedScan.url}
                </p>
              </div>

              {/* CVE/CVSS Vulnerabilities */}
              {selectedScan.vulnerabilities && selectedScan.vulnerabilities.length > 0 && (
                <div className="space-y-3">
                  <h3 className="font-semibold text-sm text-muted-foreground flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" />
                    Detected Vulnerabilities (CVE/CVSS)
                  </h3>
                  <div className="space-y-3">
                    {selectedScan.vulnerabilities.map((vuln, index) => (
                      <Card key={index} className="border-l-4 border-l-destructive">
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div className="space-y-1">
                              <CardTitle className="text-base font-mono">{vuln.id}</CardTitle>
                              <CardDescription>{vuln.description}</CardDescription>
                            </div>
                            <div className="flex flex-col items-end gap-1">
                              <Badge
                                variant="outline"
                                className={
                                  vuln.severity === 'CRITICAL'
                                    ? 'bg-destructive/10 text-destructive border-destructive/20'
                                    : vuln.severity === 'HIGH'
                                    ? 'bg-orange-500/10 text-orange-500 border-orange-500/20'
                                    : 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
                                }
                              >
                                {vuln.severity}
                              </Badge>
                              <div className="text-sm font-semibold">
                                CVSS: {vuln.cvss_score.toFixed(1)}
                              </div>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            <div className="text-sm font-semibold text-success">Remediation:</div>
                            <p className="text-sm text-muted-foreground">{vuln.remediation}</p>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>
              )}

              {/* Threat Names */}
              {selectedScan.threatNames && selectedScan.threatNames.length > 0 && (
                <div className="space-y-2">
                  <h3 className="font-semibold text-sm text-muted-foreground">Detected Threats</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedScan.threatNames.map((threat, index) => (
                      <Badge key={index} variant="outline" className="text-xs">
                        {threat}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Scan Info */}
              <div className="grid md:grid-cols-2 gap-4 pt-4 border-t">
                <div className="space-y-2">
                  <h3 className="font-semibold text-sm text-muted-foreground">Scan Time</h3>
                  <p className="text-sm">{selectedScan.timestamp}</p>
                </div>
                <div className="space-y-2">
                  <h3 className="font-semibold text-sm text-muted-foreground">Detection Engine</h3>
                  <p className="text-sm">MalwareSnipper v2.3.1 + VirusTotal</p>
                </div>
              </div>

              {/* Risk Summary */}
              <Alert className={
                selectedScan.status === 'malicious' 
                  ? 'border-destructive bg-destructive/5' 
                  : selectedScan.status === 'suspicious'
                  ? 'border-warning bg-warning/5'
                  : 'border-success bg-success/5'
              }>
                <AlertDescription className="text-sm leading-relaxed">
                  {selectedScan.status === "safe" && (
                    <p>✅ This website passed all security checks. No malicious content or suspicious patterns detected.</p>
                  )}
                  {selectedScan.status === "suspicious" && (
                    <p>⚠️ This website exhibits suspicious behavior. Proceed with caution. Review the CVE details above for specific vulnerabilities and remediation steps.</p>
                  )}
                  {selectedScan.status === "malicious" && (
                    <p className="font-medium">
                      🚨 DANGER: This website contains confirmed malware or phishing content. Do not proceed or enter any personal information. Review CVE/CVSS details above for specific threats and recommended actions.
                    </p>
                  )}
                </AlertDescription>
              </Alert>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  );
};

export default EnhancedDashboard;
