import { useState, useEffect } from "react";
import { Shield, AlertTriangle, Activity, Users, TrendingUp } from "lucide-react";
import io from 'socket.io-client';
import DashboardLayout from "@/components/DashboardLayout";
import ThreatCharts from "@/components/ThreatCharts";
import ScanTable from "@/components/ScanTable";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const BACKEND_URL = 'http://localhost:5000';

const SimpleDashboard = () => {
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    safe: 0,
    suspicious: 0,
    malicious: 0
  });
  const [connected, setConnected] = useState(false);
  const [detectionRate, setDetectionRate] = useState(0);

  useEffect(() => {
    console.log('🚀 Connecting to backend...');
    
    // WebSocket connection
    const socket = io(BACKEND_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true
    });

    socket.on('connect', () => {
      console.log('✅ Connected');
      setConnected(true);
      loadStats();
      loadHistory();
    });

    socket.on('disconnect', () => {
      console.log('❌ Disconnected');
      setConnected(false);
    });

    // Listen for new scans
    socket.on('new_scan', (data) => {
      console.log('🔔 New scan:', data.url);
      
      const scan = {
        id: Date.now().toString(),
        url: data.url,
        status: data.risk === 'safe' ? 'safe' : data.risk === 'suspicious' ? 'suspicious' : 'malicious',
        threatScore: data.score || 0,
        timestamp: new Date().toLocaleString(),
        details: data
      };
      
      setScans(prev => [scan, ...prev].slice(0, 100));
      
      // Update stats
      setStats(prev => {
        const newStats = {
          total: prev.total + 1,
          safe: prev.safe + (data.risk === 'safe' ? 1 : 0),
          suspicious: prev.suspicious + (data.risk === 'suspicious' ? 1 : 0),
          malicious: prev.malicious + (data.risk === 'malicious' ? 1 : 0)
        };
        
        // Calculate detection rate
        const rate = newStats.total > 0 
          ? parseFloat(((newStats.safe / newStats.total) * 100).toFixed(1))
          : 0;
        setDetectionRate(rate);
        
        return newStats;
      });
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  const loadStats = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/scan/stats`);
      if (res.ok) {
        const data = await res.json();
        const newStats = {
          total: data.total_scans || 0,
          safe: data.benign_count || 0,
          suspicious: data.suspicious_count || 0,
          malicious: data.malicious_count || 0
        };
        setStats(newStats);
        
        // Calculate detection rate
        const rate = newStats.total > 0 
          ? parseFloat(((newStats.safe / newStats.total) * 100).toFixed(1))
          : 0;
        setDetectionRate(rate);
      }
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const loadHistory = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/scan/history`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.scans)) {
          const formattedScans = data.scans.slice(0, 100).map((scan: any) => ({
            id: scan.id || Date.now().toString(),
            url: scan.url,
            status: scan.classification === 'BENIGN' ? 'safe' : 
                    scan.classification === 'SUSPICIOUS' ? 'suspicious' : 'malicious',
            threatScore: scan.risk_score || 0,
            timestamp: new Date(scan.timestamp).toLocaleString(),
            details: scan
          }));
          setScans(formattedScans);
        }
      }
    } catch (error) {
      console.error('Error loading history:', error);
    }
  };

  const handleViewDetails = (scan: any) => {
    console.log('View details:', scan);
    // You can add a modal here to show detailed information
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Dashboard</h1>
            <p className="text-muted-foreground">Real-time threat monitoring and analytics</p>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant={connected ? "default" : "destructive"} className="gap-2">
              <div className={`h-2 w-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
              {connected ? 'Live' : 'Disconnected'}
            </Badge>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid gap-4 md:grid-cols-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Scans</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total}</div>
              <p className="text-xs text-muted-foreground mt-1">{stats.total} total scans</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Active Threats</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.suspicious + stats.malicious}</div>
              <p className="text-xs text-muted-foreground mt-1">{stats.suspicious} suspicious</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Safe Sites</CardTitle>
              <Shield className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.safe}</div>
              <p className="text-xs text-muted-foreground mt-1">{detectionRate}% safe rate</p>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Protected Browsing</CardTitle>
              <Users className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">Live</div>
              <p className="text-xs text-muted-foreground mt-1">Real-time protection</p>
            </CardContent>
          </Card>
        </div>

        {/* Charts Section */}
        <ThreatCharts />

        {/* Tabs for Scans */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="scanlogs">Scan Logs</TabsTrigger>
          </TabsList>
          
          <TabsContent value="overview" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Recent Scans</CardTitle>
              </CardHeader>
              <CardContent>
                {scans.length === 0 ? (
                  <div className="text-center py-12">
                    <Activity className="h-12 w-12 mx-auto mb-4 opacity-50 text-muted-foreground" />
                    <p className="text-muted-foreground">Waiting for scans...</p>
                    <p className="text-sm text-muted-foreground mt-2">Visit a website to see analysis</p>
                  </div>
                ) : (
                  <ScanTable 
                    scans={scans.slice(0, 10)} 
                    onViewDetails={handleViewDetails}
                  />
                )}
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="scanlogs" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Complete Scan History</CardTitle>
              </CardHeader>
              <CardContent>
                {scans.length === 0 ? (
                  <div className="text-center py-12">
                    <Activity className="h-12 w-12 mx-auto mb-4 opacity-50 text-muted-foreground" />
                    <p className="text-muted-foreground">No scan history available</p>
                  </div>
                ) : (
                  <ScanTable 
                    scans={scans} 
                    onViewDetails={handleViewDetails}
                  />
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </DashboardLayout>
  );
};

export default SimpleDashboard;
