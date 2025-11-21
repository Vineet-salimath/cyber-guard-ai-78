import { useState, useEffect, useRef } from "react";
import { Shield, AlertTriangle, Activity, Users, Radio, Globe, Clock, TrendingUp } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import StatCard from "@/components/StatCard";
import ScanTable from "@/components/ScanTable";
import ThreatCharts from "@/components/ThreatCharts";
import { SIEMLiveLogViewer } from "@/components/SIEMLiveLogViewer";
import { RealTimeExtensionIntegration } from "@/components/RealTimeExtensionIntegration";
import { io } from 'socket.io-client';

// Import new comprehensive components
import { LiveTrafficTable } from "@/components/LiveTrafficTable";
import { RiskGraph } from "@/components/RiskGraph";
import { URLScanCard } from "@/components/URLScanCard";
import { StatsOverview } from "@/components/StatsOverview";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";

interface Scan {
  id: string;
  url: string;
  timestamp: string;
  status: "safe" | "suspicious" | "malicious" | "benign" | "phishing" | "ransomware" | "obfuscated_js";
  threatScore: number;
  classification?: string;
  indicators?: string[];
  method?: string;
  analysis?: any;
  details?: any;
}

interface TrafficEntry {
  id: number;
  url: string;
  method: string;
  status_code: number;
  type: string;
  duration: number;
  timestamp: number;
  error: string | null;
  analyzed: boolean;
  threat_level: string;
  risk_score?: number;
}

interface RealTimeStats {
  total_requests: number;
  malicious_detected: number;
  suspicious_detected: number;
  clean_urls: number;
  pending_scans: number;
  last_updated: string;
}

const BACKEND_URL = 'http://localhost:5000';

const Dashboard = () => {
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [dataSource, setDataSource] = useState<'extension' | 'backend' | 'none'>('none');
  const [isLiveConnected, setIsLiveConnected] = useState(false);
  const [stats, setStats] = useState({
    total: 0,
    safe: 0,
    suspicious: 0,
    malicious: 0,
    detectionRate: 0
  });

  // Real-time traffic monitoring
  const [realtimeTraffic, setRealtimeTraffic] = useState<TrafficEntry[]>([]);
  const [realtimeStats, setRealtimeStats] = useState<RealTimeStats>({
    total_requests: 0,
    malicious_detected: 0,
    suspicious_detected: 0,
    clean_urls: 0,
    pending_scans: 0,
    last_updated: new Date().toISOString()
  });

  const broadcastChannelRef = useRef<BroadcastChannel | null>(null);
  const messageListenerRef = useRef<((event: MessageEvent) => void) | null>(null);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // WebSocket for instant updates
  useEffect(() => {
    const socket = io(BACKEND_URL);
    
    socket.on('connect', () => {
      console.log('🔌 WebSocket connected');
      setIsLiveConnected(true);
    });
    
    socket.on('disconnect', () => {
      console.log('❌ WebSocket disconnected');
      setIsLiveConnected(false);
    });
    
    // Handle all scan status updates
    socket.on('new_scan', (data: any) => {
      console.log('🔥 Real-time event received:', data);
      
      // Handle progressive updates
      if (data.status === 'SCAN_STARTED') {
        console.log(`🚀 Scan started for ${data.url}`);
        // Show notification or progress indicator
        return;
      }
      
      if (data.status === 'SCAN_UPDATE') {
        console.log(`⏳ Scan progress: ${data.progress}% - ${data.message}`);
        // Update progress bar if needed
        return;
      }
      
      if (data.status === 'SCAN_COMPLETE' || data.threat_level || data.classification) {
        // Final result received - add to scans list
        console.log('✅ Scan complete:', data.url, data.threat_level || data.classification);
        
        // Normalize classification/threat_level to status
        let status: "safe" | "suspicious" | "malicious" | "benign" | "phishing" | "ransomware" | "obfuscated_js" = "safe";
        const threatLevel = (data.threat_level || data.classification || 'SAFE').toUpperCase();
        
        if (threatLevel === 'MALICIOUS' || threatLevel === 'RANSOMWARE') {
          status = 'malicious';
        } else if (threatLevel === 'SUSPICIOUS' || threatLevel === 'PHISHING' || threatLevel === 'OBFUSCATED_JS') {
          status = 'suspicious';
        } else if (threatLevel === 'SAFE' || threatLevel === 'BENIGN' || threatLevel === 'CLEAN') {
          status = 'safe';
        }
        
        const newScan: Scan = {
          id: data.id || String(Date.now()),
          url: data.url,
          timestamp: data.timestamp || Date.now(),
          status: status,
          threatScore: data.risk_score || 0,
          classification: data.threat_level || data.classification,
          indicators: data.indicators || [],
          method: data.method || 'EXTENSION',
          analysis: data.analysis,
          details: data.details
        };
        
        // Add to scans list (prevent duplicates)
        setScans(prev => {
          const exists = prev.some(scan => scan.url === newScan.url && Math.abs(scan.timestamp - newScan.timestamp) < 1000);
          if (exists) {
            console.log('⏭️ Duplicate scan ignored');
            return prev;
          }
          return [newScan, ...prev].slice(0, 100);
        });
        
        // Update stats
        setStats(prev => {
          const isSafe = status === 'safe';
          const isSuspicious = status === 'suspicious';
          const isMalicious = status === 'malicious';
          
          return {
            total: prev.total + 1,
            safe: prev.safe + (isSafe ? 1 : 0),
            suspicious: prev.suspicious + (isSuspicious ? 1 : 0),
            malicious: prev.malicious + (isMalicious ? 1 : 0),
            detectionRate: ((prev.safe + (isSafe ? 1 : 0)) / (prev.total + 1)) * 100
          };
        });
      }
    });
    
    return () => { socket.disconnect(); };
  }, []);

  useEffect(() => {
    // Initialize BroadcastChannel for real-time updates
    initializeBroadcastChannel();
    
    // Initialize window.postMessage listener for extension bridge
    initializeExtensionBridge();
    
    loadDashboardData();
    
    // Start real-time traffic polling
    startRealtimePolling();

    // Auto-refresh every 30 seconds as per spec
    const interval = setInterval(() => {
      loadDashboardData();
    }, 30000);

    // Listen for Chrome storage changes (real-time updates from extension)
    let storageListener: ((changes: any, areaName: string) => void) | null = null;
    
    if (typeof chrome !== 'undefined' && chrome.storage) {
      storageListener = (changes, areaName) => {
        if (areaName === 'local' && changes.autoScanHistory) {
          console.log('🔄 Extension storage updated - refreshing dashboard...');
          loadDashboardData();
        }
      };
      // @ts-ignore - Chrome extension API types
      if (chrome.storage.onChanged) {
        // @ts-ignore
        chrome.storage.onChanged.addListener(storageListener);
      }
    }

    return () => {
      clearInterval(interval);
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
      }
      if (storageListener && typeof chrome !== 'undefined' && chrome.storage) {
        // @ts-ignore - Chrome extension API types
        if (chrome.storage.onChanged) {
          // @ts-ignore
          chrome.storage.onChanged.removeListener(storageListener);
        }
      }
      // Cleanup BroadcastChannel
      if (broadcastChannelRef.current) {
        broadcastChannelRef.current.close();
      }
      // Cleanup extension bridge listener
      if (messageListenerRef.current) {
        window.removeEventListener('message', messageListenerRef.current);
      }
    };
  }, []);

  /**
   * Start real-time traffic polling
   */
  const startRealtimePolling = () => {
    console.log('🔄 [REALTIME] Starting traffic polling...');
    
    // Fetch immediately
    fetchRealtimeTraffic();
    fetchRealtimeStats();
    
    // Poll every 5 seconds for traffic updates
    pollingIntervalRef.current = setInterval(() => {
      fetchRealtimeTraffic();
      fetchRealtimeStats();
    }, 5000);
  };

  /**
   * Fetch real-time traffic from backend
   */
  const fetchRealtimeTraffic = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/dashboard/traffic?limit=50`);
      if (response.ok) {
        const data = await response.json();
        const trafficData = data.traffic || [];
        setRealtimeTraffic(trafficData);
        setIsLiveConnected(true);
        
        // Convert traffic entries to scans for the dashboard table
        if (trafficData.length > 0) {
          const convertedScans: Scan[] = trafficData.map((entry: TrafficEntry) => {
            // Map threat_level to status
            let status: "safe" | "suspicious" | "malicious" = "safe";
            const threatLevel = (entry.threat_level || 'pending').toUpperCase();
            
            if (threatLevel === 'MALICIOUS' || threatLevel === 'MALWARE') {
              status = 'malicious';
            } else if (threatLevel === 'SUSPICIOUS') {
              status = 'suspicious';
            } else if (threatLevel === 'SAFE' || threatLevel === 'CLEAN') {
              status = 'safe';
            }
            
            return {
              id: String(entry.id),
              url: entry.url,
              timestamp: new Date(entry.timestamp).toLocaleString(),
              status: status,
              threatScore: entry.risk_score || 0
            };
          });
          
          // Update scans with backend data
          setScans(prev => {
            // Merge with existing scans, avoiding duplicates
            const existingUrls = new Set(prev.map(s => s.url));
            const newScans = convertedScans.filter(s => !existingUrls.has(s.url));
            return [...newScans, ...prev].slice(0, 100);
          });
          
          console.log(`✅ [REALTIME] Loaded ${convertedScans.length} traffic entries from backend`);
        }
      } else {
        console.warn('❌ [REALTIME] Failed to fetch traffic');
        setIsLiveConnected(false);
      }
    } catch (error) {
      console.error('❌ [REALTIME] Traffic fetch error:', error);
      setIsLiveConnected(false);
    }
  };

  /**
   * Fetch real-time statistics from backend
   */
  const fetchRealtimeStats = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/dashboard/stats`);
      if (response.ok) {
        const data = await response.json();
        setRealtimeStats(data);
        
        // Sync backend stats with dashboard stats
        setStats({
          total: data.total_requests || 0,
          safe: data.clean_urls || 0,
          suspicious: data.suspicious_detected || 0,
          malicious: data.malicious_detected || 0,
          detectionRate: data.total_requests > 0 
            ? ((data.clean_urls / data.total_requests) * 100) 
            : 0
        });
        
        console.log('📊 [REALTIME] Stats synced from backend:', data);
      }
    } catch (error) {
      console.error('❌ [REALTIME] Stats fetch error:', error);
    }
  };

  /**
   * Initialize BroadcastChannel for inter-tab communication
   */
  const initializeBroadcastChannel = () => {
    try {
      if (typeof BroadcastChannel !== 'undefined') {
        broadcastChannelRef.current = new BroadcastChannel('malware-snipper-channel');
        
        broadcastChannelRef.current.onmessage = (event) => {
          handleRealtimeMessage(event.data);
        };
        
        console.log('✅ [DASHBOARD] BroadcastChannel initialized');
        setIsLiveConnected(true);
      }
    } catch (error) {
      console.warn('⚠️ [DASHBOARD] BroadcastChannel not available:', error);
      setIsLiveConnected(false);
    }
  };

  /**
   * Handle NEW_SCAN_RESULT - Add scan instantly to dashboard
   * This is the CRITICAL function for real-time updates
   */
  const handleNewScanResult = (scanData: any) => {
    console.log('🚀 [DASHBOARD] NEW SCAN RESULT received from extension:');
    console.log('   URL:', scanData.url);
    console.log('   Threat Level:', scanData.threat_level || scanData.threatLevel);
    console.log('   Risk Score:', scanData.riskScore || scanData.overall_risk_score);
    console.log('   Full Data:', scanData);

    // Map threat_level to status (handle both naming conventions)
    const threatLevel = (scanData.threat_level || scanData.threatLevel || 'SAFE').toUpperCase();
    let status: "safe" | "suspicious" | "malicious" = "safe";
    
    if (threatLevel === 'MALICIOUS') status = 'malicious';
    else if (threatLevel === 'SUSPICIOUS') status = 'suspicious';
    else status = 'safe';

    // Convert to Dashboard format
    const newScan: Scan = {
      id: scanData.url_hash || scanData.id || String(Date.now()),
      url: scanData.url,
      timestamp: new Date(scanData.timestamp || Date.now()).toLocaleString(),
      status: status,
      threatScore: scanData.riskScore || scanData.overall_risk_score || 0
    };

    console.log('✅ [DASHBOARD] Converted scan data:', newScan);

    // Add to scans list at the TOP (most recent first)
    setScans(prev => {
      console.log(`📊 [DASHBOARD] Adding scan to list (current count: ${prev.length})`);
      // Remove duplicate if exists
      const filtered = prev.filter(s => s.url !== scanData.url);
      const updated = [newScan, ...filtered].slice(0, 100); // Keep max 100
      console.log(`✅ [DASHBOARD] Updated scan list (new count: ${updated.length})`);
      return updated;
    });

    // Update stats immediately
    setStats(prev => {
      const newTotal = prev.total + 1;
      const newSafe = prev.safe + (newScan.status === 'safe' ? 1 : 0);
      const newSuspicious = prev.suspicious + (newScan.status === 'suspicious' ? 1 : 0);
      const newMalicious = prev.malicious + (newScan.status === 'malicious' ? 1 : 0);
      const newDetectionRate = newTotal > 0 ? ((newSafe / newTotal) * 100) : 0;

      console.log(`📈 [DASHBOARD] Updated stats - Total: ${newTotal}, Safe: ${newSafe}, Suspicious: ${newSuspicious}, Malicious: ${newMalicious}`);

      return {
        total: newTotal,
        safe: newSafe,
        suspicious: newSuspicious,
        malicious: newMalicious,
        detectionRate: parseFloat(newDetectionRate.toFixed(1))
      };
    });

    // If URL matches current page URL parameter, open modal automatically
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    if (targetUrl && decodeURIComponent(targetUrl) === scanData.url) {
      console.log('🎯 [DASHBOARD] Scan matches URL parameter - opening modal');
      setSelectedScan(newScan);
    }

    console.log('✅ [DASHBOARD] Scan result processing complete - UI updated');
  };

  /**
   * Handle STATS_UPDATE from extension
   */
  const handleStatsUpdate = (statsData: any) => {
    const total = statsData.totalScans || 0;
    const safe = statsData.safeSites || 0;
    const detectionRate = total > 0 ? ((safe / total) * 100).toFixed(1) : '0';

    setStats({
      total,
      safe,
      suspicious: statsData.suspiciousSites || 0,
      malicious: statsData.maliciousSites || 0,
      detectionRate: parseFloat(detectionRate)
    });
  };

  /**
   * Handle real-time broadcast messages
   */
  const handleRealtimeMessage = (data: any) => {
    switch (data.type) {
      case 'NEW_SCAN_RESULT':
        handleNewScanResult(data.data);
        break;
      case 'traffic_batch_sent':
        console.log(`📤 [REALTIME] Traffic batch sent: ${data.count} requests`);
        // Refresh traffic after batch sent
        fetchRealtimeTraffic();
        break;
      default:
        console.log('Unknown message type:', data.type);
    }
  };

  /**
   * Initialize extension bridge (window.postMessage)
   */
  const initializeExtensionBridge = () => {
    console.log('🔧 [DASHBOARD] Initializing extension bridge...');
    
    const listener = (event: MessageEvent) => {
      // Only accept messages from our extension
      if (event.data?.source !== 'malware-snipper-extension') {
        return;
      }

      console.log('🌉 [DASHBOARD] Extension message received:', event.data.type);

      // Handle different message types
      switch (event.data.type) {
        case 'NEW_SCAN_RESULT':
          console.log('📥 [DASHBOARD] Processing NEW_SCAN_RESULT...');
          handleNewScanResult(event.data.data);
          break;

        case 'STATS_UPDATE':
          console.log('📊 [DASHBOARD] Processing STATS_UPDATE...');
          handleStatsUpdate(event.data.data);
          break;

        case 'SCAN_STARTED':
          console.log('🔄 [DASHBOARD] Scan started for:', event.data.data.url);
          break;

        case 'HISTORY_CLEARED':
          console.log('🗑️ [DASHBOARD] History cleared - reloading...');
          setScans([]);
          loadDashboardData();
          break;

        case 'EXTENSION_READY':
          console.log('✅ [DASHBOARD] Extension bridge connected - Live updates ENABLED');
          setIsLiveConnected(true);
          break;

        default:
          console.log('❓ [DASHBOARD] Unknown message type:', event.data.type);
      }
    };

    messageListenerRef.current = listener;
    window.addEventListener('message', listener);
    console.log('✅ [DASHBOARD] Extension bridge listener ACTIVE - Ready for real-time updates');
  };

  const loadDashboardData = async () => {
    try {
      // Load initial data from backend
      console.log('📊 [DASHBOARD] Loading initial data from backend...');
      await fetchRealtimeTraffic();
      await fetchRealtimeStats();
      
      // Also check Chrome Extension storage for additional data
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['autoScanHistory'], async (result) => {
          const extensionHistory = result.autoScanHistory || [];
          
          if (extensionHistory.length > 0) {
            console.log(`📊 [DASHBOARD] Found ${extensionHistory.length} scans in extension storage`);
            setDataSource('extension');
            
            // Convert extension format to Dashboard format
            const formattedScans = extensionHistory.map((scan: any, index: number) => ({
              id: scan.url || `scan-${index}`,
              url: scan.url,
              timestamp: new Date(scan.timestamp).toLocaleString(),
              status: scan.threatLevel.toLowerCase() as "safe" | "suspicious" | "malicious",
              threatScore: scan.riskScore || 0
            })).slice(0, 20);
            
            // Merge with backend scans
            setScans(prev => {
              const existingUrls = new Set(prev.map(s => s.url));
              const newScans = formattedScans.filter((s: any) => !existingUrls.has(s.url));
              return [...newScans, ...prev].slice(0, 100);
            });
          }
        });
      } else {
        console.log('⚠️ [DASHBOARD] Chrome extension not detected. Showing backend data only.');
        setDataSource('none');
        setScans([]);
        setStats({
          total: 0,
          safe: 0,
          suspicious: 0,
          malicious: 0,
          detectionRate: 0
        });
      }
    } catch (error) {
      console.error('❌ Error loading dashboard data:', error);
      // Show empty state on error
      setScans([]);
      setStats({
        total: 0,
        safe: 0,
        suspicious: 0,
        malicious: 0,
        detectionRate: 0
      });
    }
  };

  return (
    <DashboardLayout>
      <div className="p-6 lg:p-8 space-y-8 max-w-7xl mx-auto">
        {/* Header with Live Status */}
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
            <p className="text-muted-foreground">Real-time threat monitoring and analytics</p>
          </div>
          
          <div className="flex items-center gap-3">
            {/* Live Connection Badge */}
            <Badge variant={isLiveConnected ? "default" : "destructive"} className="gap-2">
              <Radio className={`h-3 w-3 ${isLiveConnected ? 'animate-pulse' : ''}`} />
              {isLiveConnected ? 'Live Updates' : 'Disconnected'}
            </Badge>
            
            {/* Data Source Badge */}
            <Badge variant="outline" className="gap-2">
              {dataSource === 'extension' && '📱 Extension'}
              {dataSource === 'backend' && '🌐 API'}
              {dataSource === 'none' && '⚠️ No Data'}
            </Badge>
          </div>
        </div>

        {/* Real-Time Statistics Grid */}
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-5">
          <StatCard
            title="Total Requests"
            value={realtimeStats.total_requests.toString()}
            icon={Globe}
            trend={`${realtimeStats.total_requests} HTTP requests captured`}
            variant="default"
          />
          <StatCard
            title="Malicious Detected"
            value={realtimeStats.malicious_detected.toString()}
            icon={AlertTriangle}
            trend={`${realtimeStats.malicious_detected} threats found`}
            variant="danger"
          />
          <StatCard
            title="Clean URLs"
            value={realtimeStats.clean_urls.toString()}
            icon={Shield}
            trend={`${realtimeStats.clean_urls} safe sites`}
            variant="success"
          />
          <StatCard
            title="Pending Scans"
            value={realtimeStats.pending_scans.toString()}
            icon={Clock}
            trend={`${realtimeStats.pending_scans} awaiting analysis`}
            variant="default"
          />
          <StatCard
            title="Detection Rate"
            value={realtimeStats.total_requests > 0 
              ? `${Math.round((realtimeStats.clean_urls / realtimeStats.total_requests) * 100)}%`
              : '0%'}
            icon={TrendingUp}
            trend="Safe browsing rate"
            variant="success"
          />
        </div>

        {/* Charts - 3 charts as per spec */}
        <ThreatCharts />

        {/* Extension Integration Status */}
        <RealTimeExtensionIntegration
          onNewScan={(data) => {
            console.log('📊 [DASHBOARD] Real-time scan received:', data);
            // Add to scans list
            const newScan: Scan = {
              id: String(data.timestamp),
              url: data.url,
              timestamp: new Date(data.timestamp).toLocaleString(),
              status: (data.threat_level?.toLowerCase() || 'safe') as "safe" | "suspicious" | "malicious",
              threatScore: data.riskScore
            };
            setScans(prev => [newScan, ...prev].slice(0, 100));
            
            // Update stats
            setStats(prev => ({
              total: prev.total + 1,
              safe: prev.safe + (newScan.status === 'safe' ? 1 : 0),
              suspicious: prev.suspicious + (newScan.status === 'suspicious' ? 1 : 0),
              malicious: prev.malicious + (newScan.status === 'malicious' ? 1 : 0),
              detectionRate: prev.total > 0 ? ((prev.safe / prev.total) * 100) : 0
            }));
          }}
          onStatsUpdate={(stats) => {
            console.log('📊 [DASHBOARD] Stats update received:', stats);
            if (stats.totalScans !== undefined) {
              setStats({
                total: stats.totalScans,
                safe: stats.safeSites || 0,
                suspicious: stats.suspiciousSites || 0,
                malicious: stats.maliciousSites || 0,
                detectionRate: stats.totalScans > 0 ? ((stats.safeSites / stats.totalScans) * 100) : 0
              });
            }
          }}
          onConnectionChange={(connected) => {
            setIsLiveConnected(connected);
            setDataSource(connected ? 'extension' : 'none');
          }}
        />

        {/* Tabs: Real-Time Traffic + SIEM Live Log + Scan Table */}
        <Tabs defaultValue="traffic" className="space-y-4">
          <TabsList className="grid w-full grid-cols-3 max-w-[600px]">
            <TabsTrigger value="traffic" className="gap-2">
              <Activity className="h-4 w-4" />
              Live Traffic
            </TabsTrigger>
            <TabsTrigger value="siem" className="gap-2">
              <Radio className="h-4 w-4" />
              SIEM Log
            </TabsTrigger>
            <TabsTrigger value="table" className="gap-2">
              <Shield className="h-4 w-4" />
              Scans
            </TabsTrigger>
          </TabsList>

          {/* Real-Time Traffic Table */}
          <TabsContent value="traffic" className="space-y-4">
            <Card className="p-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold">Real-Time HTTP Traffic</h3>
                    <p className="text-sm text-muted-foreground">
                      Live capture of all HTTP/HTTPS requests with threat analysis
                    </p>
                  </div>
                  <Badge variant={isLiveConnected ? "default" : "secondary"}>
                    {realtimeTraffic.length} Requests
                  </Badge>
                </div>

                <div className="rounded-md border overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-muted/50">
                        <tr>
                          <th className="px-4 py-3 text-left font-medium">Time</th>
                          <th className="px-4 py-3 text-left font-medium">URL</th>
                          <th className="px-4 py-3 text-left font-medium">Method</th>
                          <th className="px-4 py-3 text-left font-medium">Status</th>
                          <th className="px-4 py-3 text-left font-medium">Duration</th>
                          <th className="px-4 py-3 text-left font-medium">Threat Level</th>
                        </tr>
                      </thead>
                      <tbody>
                        {realtimeTraffic.length === 0 ? (
                          <tr>
                            <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                              No traffic data yet. Browse the web with the extension installed to see real-time capture.
                            </td>
                          </tr>
                        ) : (
                          realtimeTraffic.map((traffic) => (
                            <tr
                              key={traffic.id}
                              className="border-t hover:bg-muted/30 transition-colors"
                            >
                              <td className="px-4 py-3 whitespace-nowrap">
                                {new Date(traffic.timestamp).toLocaleTimeString()}
                              </td>
                              <td className="px-4 py-3 max-w-xs truncate" title={traffic.url}>
                                {traffic.url}
                              </td>
                              <td className="px-4 py-3">
                                <Badge variant="outline" className="text-xs">
                                  {traffic.method}
                                </Badge>
                              </td>
                              <td className="px-4 py-3">
                                <Badge
                                  variant={
                                    traffic.status_code >= 200 && traffic.status_code < 300
                                      ? "default"
                                      : traffic.status_code >= 400
                                      ? "destructive"
                                      : "secondary"
                                  }
                                  className="text-xs"
                                >
                                  {traffic.status_code || 'N/A'}
                                </Badge>
                              </td>
                              <td className="px-4 py-3 whitespace-nowrap">
                                {traffic.duration ? `${traffic.duration}ms` : 'N/A'}
                              </td>
                              <td className="px-4 py-3">
                                {traffic.analyzed ? (
                                  <Badge
                                    variant={
                                      traffic.threat_level === 'MALICIOUS'
                                        ? "destructive"
                                        : traffic.threat_level === 'SUSPICIOUS'
                                        ? "secondary"
                                        : traffic.threat_level === 'SAFE'
                                        ? "default"
                                        : "outline"
                                    }
                                    className="text-xs"
                                  >
                                    {traffic.threat_level}
                                    {traffic.risk_score !== undefined && ` (${traffic.risk_score})`}
                                  </Badge>
                                ) : (
                                  <Badge variant="outline" className="text-xs">
                                    Pending
                                  </Badge>
                                )}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Refresh indicator */}
                <div className="flex items-center justify-center text-xs text-muted-foreground">
                  <Activity className="h-3 w-3 mr-2 animate-pulse" />
                  Auto-refreshing every 5 seconds
                </div>
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="siem">
            <SIEMLiveLogViewer />
          </TabsContent>

          <TabsContent value="table">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-semibold">Recent Scans</h2>
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <div className={`w-2 h-2 rounded-full ${isLiveConnected ? 'bg-success animate-pulse' : 'bg-destructive'}`} />
                  <span>{isLiveConnected ? 'Live Updates Active' : 'Offline'}</span>
                </div>
              </div>
              <ScanTable scans={scans} onViewDetails={setSelectedScan} />
            </div>
          </TabsContent>
        </Tabs>
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
