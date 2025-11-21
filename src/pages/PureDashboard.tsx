// DASHBOARD - PURE DISPLAY MODE (NO ANALYSIS, ONLY LISTENS TO BACKEND)

import { useState, useEffect } from "react";
import { Shield, AlertTriangle, Activity } from "lucide-react";
import io from 'socket.io-client';
import DashboardLayout from "@/components/DashboardLayout";
import StatCard from "@/components/StatCard";
import ScanTable from "@/components/ScanTable";
import RealtimePieChart from "@/components/RealtimePieChart";
import LiveThreatFeed from "@/components/LiveThreatFeed";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";

const BACKEND_URL = 'http://localhost:5000';

interface Scan {
  id: string;
  url: string;
  timestamp: string;
  status: "safe" | "suspicious" | "malicious";
  threatScore: number;
  threatNames?: string[];
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
}

const PureDashboard = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [scanStats, setScanStats] = useState<ScanStats>({
    total_scans: 0,
    benign_count: 0,
    suspicious_count: 0,
    malicious_count: 0,
    benign_percentage: 0,
    suspicious_percentage: 0,
    malicious_percentage: 0,
  });
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  useEffect(() => {
    console.log('🚀 [DASHBOARD] Initializing PURE LISTENER MODE');
    console.log('📡 [DASHBOARD] NO local analysis - only displays backend results');
    
    // Initialize WebSocket connection
    const socket = io(BACKEND_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    socket.on('connect', () => {
      console.log('✅ [WEBSOCKET] Connected to backend');
      setIsConnected(true);
      setConnectionError(null);
      
      // Load initial stats
      loadInitialStats();
    });

    socket.on('disconnect', (reason) => {
      console.log('❌ [WEBSOCKET] Disconnected:', reason);
      setIsConnected(false);
    });

    socket.on('connect_error', (error) => {
      console.error('❌ [WEBSOCKET] Connection error:', error);
      setConnectionError('Cannot connect to backend. Please ensure it is running on http://localhost:5000');
    });

    // Listen for new scans from backend
    socket.on('new_scan', (data) => {
      console.log('🔔 [WEBSOCKET] New scan result from backend:', data);
      
      // Create scan object
      const newScan: Scan = {
        id: `scan-${Date.now()}`,
        url: data.url,
        timestamp: new Date().toLocaleString(),
        status: data.risk === 'safe' || data.risk === 'benign' ? 'safe' :
                data.risk === 'suspicious' ? 'suspicious' : 'malicious',
        threatScore: data.score || 0,
        threatNames: data.threat_names || [],
        ml_prediction: data.ml_prediction,
        risk: data.risk,
        score: data.score
      };
      
      // Add to scans list
      setScans(prev => [newScan, ...prev].slice(0, 100));
      
      // Update stats from backend data
      if (data.stats) {
        setScanStats(data.stats);
      }
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  const loadInitialStats = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/scan/stats`);
      if (response.ok) {
        const stats = await response.json();
        setScanStats(stats);
        console.log('✅ [STATS] Loaded initial stats:', stats);
      }
    } catch (error) {
      console.error('❌ [STATS] Error loading stats:', error);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Real-Time Dashboard</h1>
            <p className="text-muted-foreground">
              Displaying analysis results from backend (Extension → Backend → Dashboard)
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className={`h-3 w-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`}></div>
            <span className="text-sm font-medium">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>

        {/* Connection Error */}
        {connectionError && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              {connectionError}
              <br />
              <span className="text-xs">Make sure the backend is running on http://localhost:5000</span>
            </AlertDescription>
          </Alert>
        )}

        {/* Stats Cards */}
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          <StatCard
            title="Total Scans"
            value={scanStats.total_scans.toString()}
            icon={Shield}
            trend={isConnected ? "+Live" : "Offline"}
            variant="default"
          />
          <StatCard
            title="Safe Sites"
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

        {/* Charts */}
        <div className="grid gap-6 lg:grid-cols-2">
          <RealtimePieChart stats={scanStats} />
          <LiveThreatFeed scans={scans} maxItems={10} />
        </div>

        {/* Scans Table */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Scans</CardTitle>
            <CardDescription>Real-time scans from extension via backend</CardDescription>
          </CardHeader>
          <CardContent>
            {scans.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>Waiting for extension to send URLs...</p>
                <p className="text-sm mt-2">Visit a website to see real-time analysis</p>
              </div>
            ) : (
              <ScanTable scans={scans.slice(0, 50)} onViewDetails={() => {}} />
            )}
          </CardContent>
        </Card>

        {/* Info Banner */}
        <Alert>
          <AlertDescription>
            <strong>🛡️ PURE DISPLAY MODE:</strong> This dashboard only displays results from the backend.
            The extension sends URLs directly to the backend, which analyzes them and broadcasts results here.
            <br />
            <span className="text-xs text-muted-foreground mt-2 block">
              Flow: Extension → Backend (Analysis) → Dashboard (Display Only)
            </span>
          </AlertDescription>
        </Alert>
      </div>
    </DashboardLayout>
  );
};

export default PureDashboard;
