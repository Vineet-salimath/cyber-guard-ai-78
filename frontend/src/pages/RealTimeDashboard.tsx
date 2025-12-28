// ============================================
// MALWARESNIPPER - REAL-TIME DASHBOARD
// 100% REAL DATA - NO DUMMY DATA
// ============================================

import { useState, useEffect, useRef } from "react";
import { Shield, AlertTriangle, Activity, ExternalLink, Bug, Info } from "lucide-react";
import io from 'socket.io-client';
import DashboardLayout from "@/components/DashboardLayout";
import DownloadDropdown from "@/components/DownloadDropdown";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, AreaChart, Area } from 'recharts';

const BACKEND_URL = 'http://localhost:5000';

interface ScanResult {
  url: string;
  domain?: string;
  final_classification?: string;  // New unified field
  classification?: string;  // Backwards compat
  overall_risk?: number;  // New unified field
  risk_score?: number;  // Backwards compat
  risk_level?: string;  // NEW: LOW, MEDIUM, HIGH, CRITICAL
  ml_confidence?: number;
  threat_indicators?: string[];
  
  // NEW: Multi-layer analysis results
  layer_scores?: {
    static_analysis: number;
    owasp_security: number;
    threat_intelligence: number;
    signature_matching: number;
    machine_learning: number;
    behavioral_heuristics: number;
  };
  
  detailed_analysis?: {
    static_analysis?: any;
    owasp_analysis?: any;
    threat_intelligence?: any;
    signature_matching?: any;
    machine_learning?: any;
    behavioral_heuristics?: any;
  };
  
  summary?: {
    total_findings?: number;
    critical_findings?: number;
    warning_findings?: number;
    info_findings?: number;
    threats_detected?: string[];
    vulnerabilities_found?: string[];
    classification?: string;
  };
  
  timestamp?: number | string;
  analysis_duration?: number;
  
  page_data?: {
    title?: string;
    scripts?: number;
    inline_scripts?: number;
    resources?: number;
    forms?: number;
    iframes?: number;
  };
  analysis_time?: number;
  analysis_duration?: number;
  timestamp: string;
}

const RealTimeDashboard = () => {
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [connected, setConnected] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [scanProgress, setScanProgress] = useState<{ url: string; progress: number; phase: string } | null>(null);
  
  const socketRef = useRef<any>(null);
  const scanFeedRef = useRef<HTMLDivElement>(null);

  // ========================================
  // REAL-TIME STATS (COMPUTED FROM ACTUAL SCANS)
  // ========================================
  const stats = {
    total: scanHistory.length,
    benign: scanHistory.filter(s => (s.final_classification || s.classification) === 'BENIGN').length,
    suspicious: scanHistory.filter(s => (s.final_classification || s.classification) === 'SUSPICIOUS').length,
    malicious: scanHistory.filter(s => (s.final_classification || s.classification) === 'MALICIOUS').length
  };

  const detectionRate = stats.total > 0 ? Math.round((stats.benign / stats.total) * 100) : 0;

  // ========================================
  // WEBSOCKET CONNECTION - REAL-TIME UPDATES
  // ========================================
  useEffect(() => {
    console.log('🚀 Connecting to backend WebSocket...');
    
    const socket = io(BACKEND_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      console.log('✅ Connected to backend - Ready for real-time updates');
      setConnected(true);
    });

    socket.on('disconnect', () => {
      console.log('❌ Disconnected from backend');
      setConnected(false);
    });

    // 🔥 CRITICAL: Listen for REAL scan results from extension
    // Backend emits 'new_scan' event
    socket.on('new_scan', (data: any) => {
      console.log('🔔 NEW REAL-TIME SCAN RECEIVED:', data);
      console.log('   📍 URL:', data.url);
      console.log('   ⚠️  Risk:', data.risk_score || data.overall_risk);
      console.log('   🎯 Classification:', data.classification || data.final_classification || data.threat_level);
      
      // Skip progress updates, only process complete scans
      if (data.status === 'SCAN_STARTED' || data.status === 'SCAN_UPDATE') {
        console.log(`   ⏳ Progress update: ${data.message || data.status}`);
        setScanning(true);
        return;
      }
      
      setScanning(false);
      
      // Normalize the data format
      const normalizedScan: ScanResult = {
        url: data.url,
        domain: data.domain,
        final_classification: data.final_classification || data.classification || data.threat_level || 'BENIGN',
        classification: data.classification || data.final_classification || data.threat_level || 'BENIGN',
        overall_risk: data.overall_risk || data.risk_score || 0,
        risk_score: data.risk_score || data.overall_risk || 0,
        risk_level: data.risk_level,
        ml_confidence: data.ml_confidence,
        threat_indicators: data.indicators || data.threat_indicators || [],
        layer_scores: data.layer_scores || data.analysis,
        detailed_analysis: data.detailed_analysis || data.details,
        summary: data.summary || data.details,
        timestamp: data.timestamp || Date.now(),
        analysis_duration: data.analysis_duration
      };
      
      console.log('   ✅ Normalized scan data:', normalizedScan);
      
      // Add to history - REAL DATA
      setScanHistory(prev => {
        const updated = [normalizedScan, ...prev].slice(0, 100); // Keep last 100 scans
        console.log('📜 Updated scan history. Total scans:', updated.length);
        return updated;
      });
      
      // Update stats
      setStats(prev => {
        const classification = normalizedScan.final_classification?.toUpperCase() || 'BENIGN';
        const isBenign = classification === 'BENIGN' || classification === 'SAFE';
        const isSuspicious = classification === 'SUSPICIOUS';
        const isMalicious = classification === 'MALICIOUS';
        
        return {
          total: prev.total + 1,
          benign: prev.benign + (isBenign ? 1 : 0),
          suspicious: prev.suspicious + (isSuspicious ? 1 : 0),
          malicious: prev.malicious + (isMalicious ? 1 : 0)
        };
      });
      
      // Auto-scroll to latest
      if (scanFeedRef.current) {
        scanFeedRef.current.scrollTop = 0;
      }
    });

    socket.on('scan_started', (data: any) => {
      console.log('⏳ Scan started:', data.url);
      setScanning(true);
    });

    // 🔥 NEW: INSTANT SCAN RESULTS (PHASE 1 - 33% progress)
    socket.on('instant_results', (data: any) => {
      console.log('⚡ INSTANT RESULTS RECEIVED (Phase 1):', data.url);
      console.log('   Progress: 33% - URL Analysis & Cache Lookup');
      
      setScanProgress({
        url: data.url,
        progress: 33,
        phase: 'instant'
      });
      setScanning(true);
    });

    // 🔥 NEW: FAST SCAN RESULTS (PHASE 2 - 66% progress)
    socket.on('scan_progress', (data: any) => {
      console.log('📊 FAST SCAN RESULTS RECEIVED (Phase 2):', data.url);
      console.log('   Progress: 66% - VirusTotal & Threat Intelligence');
      
      const vtResult = data.checks?.virustotal;
      if (vtResult?.successful) {
        console.log(`   VirusTotal: ${vtResult.malicious}/${vtResult.total} detected as malicious`);
      }
      
      setScanProgress({
        url: data.url,
        progress: 66,
        phase: 'fast'
      });
    });

    // 🔥 NEW: COMPLETE SCAN RESULTS (PHASE 3 - 100% progress)
    socket.on('scan_complete', (data: any) => {
      console.log('🎯 SCAN COMPLETE (Phase 3):', data.url);
      console.log('   Progress: 100% - Final Classification Ready');
      console.log(`   Classification: ${data.classification}`);
      console.log(`   Risk Score: ${data.riskScore}`);
      
      setScanProgress({
        url: data.url,
        progress: 100,
        phase: 'complete'
      });
      
      // Brief delay before clearing progress (for visual feedback)
      setTimeout(() => {
        setScanProgress(null);
      }, 2000);
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  // ========================================
  // CHART DATA - 100% REAL, NO DUMMY DATA
  // ========================================
  
  // 1. THREAT TYPE DISTRIBUTION (PIE CHART)
  const threatTypeData = [
    { name: 'Benign', value: stats.benign, color: '#10b981', label: 'Safe' },
    { name: 'Suspicious', value: stats.suspicious, color: '#f59e0b', label: 'Suspicious' },
    { name: 'Malicious', value: stats.malicious, color: '#ef4444', label: 'Malicious' }
  ].filter(item => item.value > 0);

  // 2. THREAT LEVELS OVER TIME (LINE/AREA CHART) - Last 20 scans
  const threatTimelineData = scanHistory
    .slice(0, 20)
    .reverse()
    .map((scan, idx) => {
      const time = new Date(scan.timestamp);
      return {
        index: idx + 1,
        time: time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        riskScore: scan.risk_score,
        label: scan.classification,
        url: scan.url
      };
    });

  // 3. TOP MALICIOUS DOMAINS (BAR CHART) - Real cumulative
  const domainCounts = scanHistory
    .filter(scan => scan.classification === 'MALICIOUS' || scan.classification === 'SUSPICIOUS')
    .reduce((acc, scan) => {
      try {
        const domain = new URL(scan.url).hostname;
        acc[domain] = (acc[domain] || 0) + 1;
        return acc;
      } catch {
        return acc;
      }
    }, {} as Record<string, number>);

  const topMaliciousDomains = Object.entries(domainCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([domain, count]) => ({ domain, count }));

  // ========================================
  // OPEN DETAILS MODAL
  // ========================================
  const openDetails = (scan: ScanResult) => {
    setSelectedScan(scan);
    setShowDetailModal(true);
  };

  const getClassificationBadge = (classification: string) => {
    const variants = {
      'BENIGN': 'bg-green-500',
      'SUSPICIOUS': 'bg-yellow-500',
      'MALICIOUS': 'bg-red-500',
      'ERROR': 'bg-gray-500'
    };
    return variants[classification as keyof typeof variants] || 'bg-gray-500';
  };

  return (
    <DashboardLayout>
      <div className="space-y-6 p-6 bg-gray-50">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">MalwareSnipper Dashboard</h1>
            <p className="text-gray-500">Real-time threat detection and analysis</p>
          </div>
          <Badge variant={connected ? "default" : "destructive"} className="gap-2 px-4 py-2">
            <div className={`h-2 w-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
            <span className="font-semibold">{connected ? 'Live' : 'Disconnected'}</span>
          </Badge>
        </div>

        {/* 🔥 PROGRESSIVE SCAN INDICATOR - REAL-TIME PROGRESS */}
        {scanProgress && (
          <Card className="bg-gradient-to-r from-blue-50 to-cyan-50 border-blue-300">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold text-blue-900">
                  {scanProgress.phase === 'instant' && '⚡ Instant Analysis...'}
                  {scanProgress.phase === 'fast' && '📊 Fast Scan Running...'}
                  {scanProgress.phase === 'complete' && '✅ Scan Complete!'}
                </CardTitle>
                <div className="text-2xl font-bold text-blue-600">{scanProgress.progress}%</div>
              </div>
              <p className="text-xs text-blue-600 mt-1">{scanProgress.url}</p>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {/* Progress bar */}
                <div className="w-full bg-blue-200 rounded-full h-3 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-blue-500 to-cyan-500 h-full transition-all duration-500"
                    style={{ width: `${scanProgress.progress}%` }}
                  />
                </div>
                
                {/* Phase indicators */}
                <div className="flex gap-3 text-xs text-blue-700">
                  <div className={`flex items-center gap-1 ${scanProgress.progress >= 33 ? 'text-blue-900 font-semibold' : 'text-blue-400'}`}>
                    ⚡ Instant
                  </div>
                  <div className={`flex items-center gap-1 ${scanProgress.progress >= 66 ? 'text-blue-900 font-semibold' : 'text-blue-400'}`}>
                    📊 Fast
                  </div>
                  <div className={`flex items-center gap-1 ${scanProgress.progress >= 100 ? 'text-blue-900 font-semibold' : 'text-blue-400'}`}>
                    🎯 Deep
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Stats Cards - REAL DATA ONLY */}
        <div className="grid gap-4 md:grid-cols-4">
          <Card className="bg-gradient-to-br from-blue-50 to-blue-100 border-blue-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-blue-700">Total Scans</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-5xl font-bold text-blue-900">{stats.total}</div>
                <Shield className="h-12 w-12 text-blue-500 opacity-50" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-gradient-to-br from-green-50 to-green-100 border-green-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-green-700">Safe</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-5xl font-bold text-green-900">{stats.benign}</div>
                <Shield className="h-12 w-12 text-green-500 opacity-50" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-gradient-to-br from-yellow-50 to-yellow-100 border-yellow-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-yellow-700">Suspicious</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-5xl font-bold text-yellow-900">{stats.suspicious}</div>
                <AlertTriangle className="h-12 w-12 text-yellow-500 opacity-50" />
              </div>
              <p className="text-xs text-yellow-600 mt-1">Flagged for review</p>
            </CardContent>
          </Card>
          
          <Card className="bg-gradient-to-br from-red-50 to-red-100 border-red-200">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-red-700">Malicious</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="text-5xl font-bold text-red-900">{stats.malicious}</div>
                <Bug className="h-12 w-12 text-red-500 opacity-50" />
              </div>
              <p className="text-xs text-red-600 mt-1">Confirmed threats</p>
            </CardContent>
          </Card>
        </div>

        {/* REAL-TIME CHARTS - NO DUMMY DATA */}
        <div className="grid gap-6 lg:grid-cols-3">
          {/* 1. THREAT TYPE DISTRIBUTION */}
          <Card className="bg-white border-gray-200">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-gray-900">Threat Type Distribution</CardTitle>
              <p className="text-xs text-gray-500">Real-time scan classifications</p>
            </CardHeader>
            <CardContent className="flex items-center justify-center h-[300px]">
              {stats.total > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatTypeData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={5}
                      dataKey="value"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {threatTypeData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-center text-gray-400">
                  <Activity className="h-12 w-12 mx-auto mb-2 opacity-50" />
                  <p className="font-medium">No Scans Yet</p>
                  <p className="text-xs mt-1">Visit websites to generate real data</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* 2. THREAT LEVELS OVER TIME */}
          <Card className="bg-white border-gray-200">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-gray-900">Threat Levels Over Time</CardTitle>
              <p className="text-xs text-gray-500">Last {threatTimelineData.length} scans - Live monitoring</p>
            </CardHeader>
            <CardContent className="h-[300px]">
              {threatTimelineData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={threatTimelineData}>
                    <defs>
                      <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                    <XAxis 
                      dataKey="time" 
                      stroke="#6b7280"
                      tick={{ fontSize: 10 }}
                      angle={-45}
                      textAnchor="end"
                      height={60}
                    />
                    <YAxis 
                      stroke="#6b7280"
                      domain={[0, 100]}
                      label={{ value: 'Risk Score %', angle: -90, position: 'insideLeft' }}
                    />
                    <Tooltip 
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          const data = payload[0].payload;
                          return (
                            <div className="bg-white p-3 border rounded shadow-lg">
                              <p className="text-xs font-semibold truncate max-w-[200px]">{data.url}</p>
                              <p className="text-sm font-bold text-red-600">Risk: {data.riskScore}%</p>
                              <p className="text-xs text-gray-600">{data.label}</p>
                              <p className="text-xs text-gray-500">{data.time}</p>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="riskScore" 
                      stroke="#ef4444" 
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#colorRisk)"
                      name="Risk Score"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-center text-gray-400">
                  <div>
                    <Activity className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p className="font-medium">No Timeline Data</p>
                    <p className="text-xs mt-1">Scan activity will appear here in real-time</p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* 3. TOP MALICIOUS DOMAINS */}
          <Card className="bg-white border-gray-200">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-gray-900">Top Malicious Domains</CardTitle>
              <p className="text-xs text-gray-500">Cumulative threat detections</p>
            </CardHeader>
            <CardContent className="h-[300px]">
              {topMaliciousDomains.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={topMaliciousDomains} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                    <XAxis 
                      type="number" 
                      stroke="#6b7280"
                      label={{ value: 'Detections', position: 'insideBottom', offset: -5 }}
                    />
                    <YAxis 
                      dataKey="domain" 
                      type="category" 
                      width={150} 
                      stroke="#6b7280"
                      tick={{ fontSize: 11 }}
                    />
                    <Tooltip 
                      content={({ active, payload }) => {
                        if (active && payload && payload.length) {
                          return (
                            <div className="bg-white p-2 border rounded shadow">
                              <p className="text-xs font-semibold">{payload[0].payload.domain}</p>
                              <p className="text-xs text-red-600 font-bold">
                                {payload[0].value} threat{payload[0].value > 1 ? 's' : ''} detected
                              </p>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    <Bar dataKey="count" fill="#f59e0b" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-center text-gray-400">
                  <div>
                    <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p className="font-medium">No Threats Detected</p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* LIVE ACTIVITY FEED - MOST RECENT SCANS */}
        <Card className="bg-white border-gray-200">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-lg font-semibold text-gray-900">Live Activity Feed</CardTitle>
                <p className="text-xs text-gray-500">Real-time scan results from your extension</p>
              </div>
              {scanning && (
                <Badge className="bg-blue-500 animate-pulse">
                  <Activity className="h-3 w-3 mr-1 animate-spin" />
                  Scanning...
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[400px]" ref={scanFeedRef}>
              {scanHistory.length === 0 ? (
                <div className="text-center py-12 text-gray-400">
                  <Activity className="h-16 w-16 mx-auto mb-4 opacity-50" />
                  <p className="text-lg font-medium">No Scans Yet</p>
                  <p className="text-sm mt-2">
                    Load the MalwareSnipper extension and visit websites.<br/>
                    Real-time scan results will appear here instantly!
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-gray-50 border-b-2 border-gray-200 sticky top-0">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Time</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">URL/Domain</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Risk Score</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Classification</th>
                        <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {scanHistory.map((scan, idx) => (
                        <tr 
                          key={idx}
                          className={`hover:bg-gray-50 transition-colors ${
                            scan.risk_score > 75 ? 'bg-red-50' : ''
                          }`}
                        >
                          <td className="px-4 py-3 text-xs text-gray-600 whitespace-nowrap">
                            {new Date(scan.timestamp).toLocaleTimeString()}
                          </td>
                          <td className="px-4 py-3 text-sm">
                            <div className={`max-w-md truncate ${scan.risk_score > 75 ? 'text-red-700 font-medium' : 'text-gray-900'}`} title={scan.url}>
                              {scan.url}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <span className={`text-sm font-bold ${
                                scan.risk_score > 75 ? 'text-red-600' :
                                scan.risk_score > 40 ? 'text-yellow-600' :
                                'text-green-600'
                              }`}>
                                {scan.risk_score}%
                              </span>
                              <div className="w-20 bg-gray-200 rounded-full h-2">
                                <div 
                                  className={`h-2 rounded-full ${
                                    scan.risk_score > 75 ? 'bg-red-500' :
                                    scan.risk_score > 40 ? 'bg-yellow-500' :
                                    'bg-green-500'
                                  }`}
                                  style={{ width: `${scan.risk_score}%` }}
                                />
                              </div>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <Badge className={`${getClassificationBadge(scan.classification)} text-white`}>
                              {scan.classification}
                            </Badge>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => openDetails(scan)}
                                className="text-xs"
                              >
                                <Info className="h-3 w-3 mr-1" />
                                Details
                              </Button>
                              <DownloadDropdown scan={scan} />
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      {/* ENHANCED THREAT REPORT MODAL */}
      <Dialog open={showDetailModal} onOpenChange={setShowDetailModal}>
        <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-xl font-bold">
              Threat Report
            </DialogTitle>
            <DialogDescription className="text-gray-500">
              Detailed analysis of the scanned website
            </DialogDescription>
          </DialogHeader>

          {selectedScan && (
            <div className="space-y-6 py-4">
              
              {/* RISK SUMMARY */}
              <div className="flex items-center gap-4">
                <Badge 
                  className={`text-base px-4 py-2 ${
                    (selectedScan.final_classification || selectedScan.classification) === 'BENIGN' 
                      ? 'bg-green-500 text-white' 
                      : (selectedScan.final_classification || selectedScan.classification) === 'MALICIOUS'
                      ? 'bg-red-500 text-white'
                      : 'bg-yellow-500 text-white'
                  }`}
                >
                  {(selectedScan.final_classification || selectedScan.classification) || 'UNKNOWN'}
                </Badge>
                <div className="text-5xl font-bold text-gray-800">
                  {(selectedScan.overall_risk || selectedScan.risk_score || 0).toFixed(0)}%
                </div>
              </div>

              {/* WEBSITE URL */}
              <div>
                <label className="text-sm font-semibold text-gray-600">Website URL</label>
                <code className="block text-sm bg-gray-50 border border-gray-200 p-3 rounded mt-1 break-all">
                  {selectedScan.url}
                </code>
              </div>

              {/* METADATA GRID */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-semibold text-gray-600">Scan Time</label>
                  <div className="text-sm text-gray-800 mt-1">
                    {new Date(selectedScan.timestamp).toLocaleString()}
                  </div>
                </div>
              </div>

              {/* RISK SUMMARY BOX */}
              <div className="bg-gray-50 border border-gray-200 p-4 rounded-lg">
                <label className="text-sm font-semibold text-gray-700 mb-2 block">Risk Summary</label>
                <p className="text-sm text-gray-700">
                  {(selectedScan.final_classification || selectedScan.classification) === 'BENIGN' 
                    ? "This website passed all security checks. No malicious content or suspicious patterns detected."
                    : (selectedScan.final_classification || selectedScan.classification) === 'MALICIOUS'
                    ? "This website was flagged as malicious. Multiple security threats detected. Avoid entering personal information."
                    : "This website exhibits suspicious patterns. Exercise caution when interacting with this site."
                  }
                </p>
              </div>

              {/* THREATS DETECTED */}
              {selectedScan.summary?.threats_detected && selectedScan.summary.threats_detected.length > 0 && (
                <div>
                  <label className="text-sm font-semibold text-gray-700 mb-2 block">Threats Detected</label>
                  <div className="space-y-1">
                    {selectedScan.summary.threats_detected.slice(0, 5).map((threat, idx) => (
                      <div key={idx} className="flex items-start gap-2 bg-red-50 border border-red-200 p-2 rounded text-sm text-red-700">
                        <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                        {threat}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* FALLBACK: Show old threat_indicators if no summary */}
              {!selectedScan.summary && selectedScan.threat_indicators && selectedScan.threat_indicators.length > 0 && (
                <div>
                  <label className="text-sm font-semibold text-gray-700 mb-2 block">Threat Indicators</label>
                  <div className="space-y-1">
                    {selectedScan.threat_indicators.map((indicator, idx) => (
                      <div key={idx} className="flex items-start gap-2 bg-red-50 border border-red-200 p-2 rounded text-sm text-red-700">
                        <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                        {indicator}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* PAGE ANALYSIS */}
              {selectedScan.page_data && (
                <div>
                  <label className="text-sm font-semibold text-gray-700 mb-2 block">Page Analysis</label>
                  <div className="grid grid-cols-3 gap-2">
                    <div className="bg-blue-50 border border-blue-200 p-2 rounded text-center">
                      <div className="text-xs text-blue-600">Scripts</div>
                      <div className="text-lg font-bold text-blue-900">{selectedScan.page_data.scripts || 0}</div>
                    </div>
                    <div className="bg-yellow-50 border border-yellow-200 p-2 rounded text-center">
                      <div className="text-xs text-yellow-600">Inline Scripts</div>
                      <div className="text-lg font-bold text-yellow-900">{selectedScan.page_data.inline_scripts || 0}</div>
                    </div>
                    <div className="bg-purple-50 border border-purple-200 p-2 rounded text-center">
                      <div className="text-xs text-purple-600">iFrames</div>
                      <div className="text-lg font-bold text-purple-900">{selectedScan.page_data.iframes || 0}</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  );
};

export default RealTimeDashboard;
