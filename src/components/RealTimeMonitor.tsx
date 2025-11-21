// REAL-TIME MONITOR - Live feed of scans from Chrome extension
import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import DashboardLayout from '@/components/DashboardLayout';

interface ScanEntry {
  url: string;
  threat_level: string;
  risk_score: number;
  stats: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
  };
  threat_names: string[];
  timestamp: number;
  scan_date: string;
}

const RealTimeMonitor = () => {
  const [scans, setScans] = useState<ScanEntry[]>([]);
  const [isLive, setIsLive] = useState(true);

  useEffect(() => {
    // Load initial scan history from Chrome storage
    loadScanHistory();

    // Poll for updates every 2 seconds
    const interval = setInterval(() => {
      if (isLive) {
        loadScanHistory();
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [isLive]);

  const loadScanHistory = () => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['autoScanHistory'], (result) => {
        if (result.autoScanHistory) {
          setScans(result.autoScanHistory);
        }
      });
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'SAFE':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'SUSPICIOUS':
        return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      case 'MALICIOUS':
        return <Shield className="w-5 h-5 text-red-500" />;
      default:
        return <Clock className="w-5 h-5 text-gray-500" />;
    }
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'SAFE':
        return 'bg-green-50 border-green-200';
      case 'SUSPICIOUS':
        return 'bg-yellow-50 border-yellow-200';
      case 'MALICIOUS':
        return 'bg-red-50 border-red-200';
      default:
        return 'bg-gray-50 border-gray-200';
    }
  };

  const formatTimeAgo = (timestamp: number) => {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  return (
    <DashboardLayout>
      <div className="p-6 lg:p-8 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Real-Time Monitor</h1>
            <p className="text-muted-foreground">Live feed of all scanned websites</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${isLive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
              <span className="text-sm font-medium">{isLive ? 'Live' : 'Paused'}</span>
            </div>
            <button
              onClick={() => setIsLive(!isLive)}
              className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90 transition"
            >
              {isLive ? 'Pause' : 'Resume'}
            </button>
          </div>
        </div>

        {/* Stats Bar */}
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-white p-4 rounded-lg border">
            <div className="text-sm text-gray-600">Total Scans</div>
            <div className="text-2xl font-bold">{scans.length}</div>
          </div>
          <div className="bg-green-50 p-4 rounded-lg border border-green-200">
            <div className="text-sm text-green-700">Safe</div>
            <div className="text-2xl font-bold text-green-600">
              {scans.filter(s => s.threat_level === 'SAFE').length}
            </div>
          </div>
          <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-200">
            <div className="text-sm text-yellow-700">Suspicious</div>
            <div className="text-2xl font-bold text-yellow-600">
              {scans.filter(s => s.threat_level === 'SUSPICIOUS').length}
            </div>
          </div>
          <div className="bg-red-50 p-4 rounded-lg border border-red-200">
            <div className="text-sm text-red-700">Malicious</div>
            <div className="text-2xl font-bold text-red-600">
              {scans.filter(s => s.threat_level === 'MALICIOUS').length}
            </div>
          </div>
        </div>

        {/* Scan Feed */}
        <div className="bg-white rounded-lg border">
          <div className="p-4 border-b">
            <h2 className="font-semibold">Recent Scans</h2>
          </div>
          <div className="divide-y max-h-[600px] overflow-y-auto">
            {scans.length === 0 ? (
              <div className="p-12 text-center text-gray-500">
                <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No scans yet. Install the Chrome extension to start monitoring.</p>
              </div>
            ) : (
              scans.map((scan, index) => (
                <div
                  key={index}
                  className={`p-4 hover:bg-gray-50 transition ${getThreatColor(scan.threat_level)} border-l-4`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3 flex-1">
                      {getThreatIcon(scan.threat_level)}
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-sm truncate">{scan.url}</div>
                        <div className="flex items-center gap-4 mt-1 text-xs text-gray-600">
                          <span>Risk: {scan.risk_score.toFixed(1)}%</span>
                          <span>•</span>
                          <span>{formatTimeAgo(scan.timestamp)}</span>
                          {scan.threat_names.length > 0 && (
                            <>
                              <span>•</span>
                              <span className="text-red-600">{scan.threat_names.length} threats</span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        scan.threat_level === 'SAFE' ? 'bg-green-100 text-green-700' :
                        scan.threat_level === 'SUSPICIOUS' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-red-100 text-red-700'
                      }`}>
                        {scan.threat_level}
                      </span>
                    </div>
                  </div>
                  {scan.threat_names.length > 0 && (
                    <div className="mt-2 ml-8 text-xs text-red-600">
                      Threats: {scan.threat_names.slice(0, 3).join(', ')}
                      {scan.threat_names.length > 3 && ` +${scan.threat_names.length - 3} more`}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default RealTimeMonitor;
