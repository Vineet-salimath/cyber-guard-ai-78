// LOG VIEWER - Searchable and filterable scan history
import { useState, useEffect } from 'react';
import { Search, Download, Filter, Calendar, ExternalLink } from 'lucide-react';
import DashboardLayout from '@/components/DashboardLayout';
import ThreatDetailsModal from '@/components/ThreatDetailsModal';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

interface ScanLog {
  id: string;
  url: string;
  timestamp: string;
  threatLevel: string;
  riskScore: number;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

const LogViewer = () => {
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [filteredLogs, setFilteredLogs] = useState<ScanLog[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [sortBy, setSortBy] = useState('recent');
  const [selectedThreat, setSelectedThreat] = useState<any>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const handleURLClick = (log: ScanLog) => {
    // Convert log format to threat data format for modal
    const threatData = {
      url: log.url,
      threat_level: log.threatLevel,
      overall_risk_score: log.riskScore,
      stats: {
        malicious: log.malicious,
        suspicious: log.suspicious,
        harmless: log.harmless,
        undetected: log.undetected
      },
      threat_names: log.malicious > 0 ? ['Threat.Detected', 'Malware.Generic'] : [],
      scan_date: log.timestamp
    };
    
    setSelectedThreat(threatData);
    setIsModalOpen(true);
  };

  useEffect(() => {
    loadLogs();

    // Refresh every 5 seconds
    const interval = setInterval(() => {
      loadLogs();
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    applyFilters();
  }, [searchQuery, filterStatus, sortBy, logs]);

  const loadLogs = () => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['autoScanHistory'], (result) => {
        const history = result.autoScanHistory || [];
        
        const formattedLogs = history.map((scan: any, index: number) => ({
          id: `log-${index}`,
          url: scan.url,
          timestamp: new Date(scan.timestamp).toISOString(),
          threatLevel: scan.threatLevel,
          riskScore: scan.riskScore || 0,
          malicious: scan.stats?.malicious || 0,
          suspicious: scan.stats?.suspicious || 0,
          harmless: scan.stats?.harmless || 0,
          undetected: scan.stats?.undetected || 0
        }));

        setLogs(formattedLogs);
      });
    } else {
      // Mock data
      const mockLogs: ScanLog[] = [
        {
          id: '1',
          url: 'https://safe-site.com',
          timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
          threatLevel: 'SAFE',
          riskScore: 5,
          malicious: 0,
          suspicious: 2,
          harmless: 68,
          undetected: 5
        },
        {
          id: '2',
          url: 'https://malware-detected.org',
          timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
          threatLevel: 'MALICIOUS',
          riskScore: 92,
          malicious: 45,
          suspicious: 15,
          harmless: 10,
          undetected: 5
        },
        {
          id: '3',
          url: 'https://suspicious-link.net',
          timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
          threatLevel: 'SUSPICIOUS',
          riskScore: 65,
          malicious: 0,
          suspicious: 25,
          harmless: 40,
          undetected: 10
        }
      ];
      setLogs(mockLogs);
    }
  };

  const applyFilters = () => {
    let filtered = [...logs];

    // Search filter
    if (searchQuery) {
      filtered = filtered.filter(log =>
        log.url.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Status filter
    if (filterStatus !== 'all') {
      filtered = filtered.filter(log => 
        log.threatLevel.toLowerCase() === filterStatus.toLowerCase()
      );
    }

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'recent':
          return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
        case 'oldest':
          return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
        case 'risk-high':
          return b.riskScore - a.riskScore;
        case 'risk-low':
          return a.riskScore - b.riskScore;
        default:
          return 0;
      }
    });

    setFilteredLogs(filtered);
  };

  const exportToCSV = () => {
    const headers = ['Timestamp', 'URL', 'Threat Level', 'Risk Score', 'Malicious', 'Suspicious', 'Harmless', 'Undetected'];
    const rows = filteredLogs.map(log => [
      new Date(log.timestamp).toLocaleString(),
      log.url,
      log.threatLevel,
      log.riskScore,
      log.malicious,
      log.suspicious,
      log.harmless,
      log.undetected
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-logs-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const getThreatBadgeColor = (level: string) => {
    switch (level) {
      case 'SAFE':
        return 'bg-green-100 text-green-700 border-green-200';
      case 'SUSPICIOUS':
        return 'bg-yellow-100 text-yellow-700 border-yellow-200';
      case 'MALICIOUS':
        return 'bg-red-100 text-red-700 border-red-200';
      default:
        return 'bg-gray-100 text-gray-700 border-gray-200';
    }
  };

  const formatTimestamp = (isoString: string) => {
    const date = new Date(isoString);
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  return (
    <DashboardLayout>
      <div className="p-6 lg:p-8 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Scan Logs</h1>
            <p className="text-muted-foreground">
              Complete history of all scanned websites
            </p>
          </div>
          <Button onClick={exportToCSV} className="flex items-center gap-2">
            <Download className="w-4 h-4" />
            Export CSV
          </Button>
        </div>

        {/* Filters */}
        <Card className="p-4">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <Input
                placeholder="Search by URL..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>

            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger>
                <Filter className="w-4 h-4 mr-2" />
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="safe">Safe Only</SelectItem>
                <SelectItem value="suspicious">Suspicious Only</SelectItem>
                <SelectItem value="malicious">Malicious Only</SelectItem>
              </SelectContent>
            </Select>

            <Select value={sortBy} onValueChange={setSortBy}>
              <SelectTrigger>
                <Calendar className="w-4 h-4 mr-2" />
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="recent">Most Recent</SelectItem>
                <SelectItem value="oldest">Oldest First</SelectItem>
                <SelectItem value="risk-high">Highest Risk</SelectItem>
                <SelectItem value="risk-low">Lowest Risk</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="mt-4 flex items-center gap-4 text-sm text-gray-600">
            <span>Showing {filteredLogs.length} of {logs.length} logs</span>
            {searchQuery && (
              <span className="bg-blue-100 text-blue-700 px-2 py-1 rounded text-xs">
                Search: "{searchQuery}"
              </span>
            )}
            {filterStatus !== 'all' && (
              <span className="bg-purple-100 text-purple-700 px-2 py-1 rounded text-xs capitalize">
                Filter: {filterStatus}
              </span>
            )}
          </div>
        </Card>

        {/* Logs Table */}
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    URL
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Risk Score
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Detections
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-12 text-center text-gray-500">
                      No logs found matching your filters
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                        {formatTimestamp(log.timestamp)}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <button
                          onClick={() => handleURLClick(log)}
                          className="text-blue-600 hover:text-blue-800 hover:underline flex items-center gap-1 max-w-md truncate cursor-pointer text-left"
                        >
                          <span className="truncate">{log.url}</span>
                          <ExternalLink className="w-3 h-3 flex-shrink-0" />
                        </button>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-3 py-1 rounded-full text-xs font-medium border ${getThreatBadgeColor(log.threatLevel)}`}>
                          {log.threatLevel}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <div className="w-24 bg-gray-200 rounded-full h-2">
                            <div
                              className={`h-full rounded-full ${
                                log.riskScore > 70 ? 'bg-red-500' :
                                log.riskScore > 30 ? 'bg-yellow-500' :
                                'bg-green-500'
                              }`}
                              style={{ width: `${log.riskScore}%` }}
                            />
                          </div>
                          <span className="text-sm font-medium">{log.riskScore}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <div className="flex gap-3">
                          {log.malicious > 0 && (
                            <span className="text-red-600 font-medium">{log.malicious} 🚨</span>
                          )}
                          {log.suspicious > 0 && (
                            <span className="text-yellow-600">{log.suspicious} ⚠️</span>
                          )}
                          {log.harmless > 0 && (
                            <span className="text-green-600">{log.harmless} ✓</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Summary */}
        <Card className="p-4 bg-gradient-to-r from-gray-50 to-blue-50">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-700">
              Total Scans: <strong>{logs.length}</strong>
            </span>
            <span className="text-green-700">
              Safe: <strong>{logs.filter(l => l.threatLevel === 'SAFE').length}</strong>
            </span>
            <span className="text-yellow-700">
              Suspicious: <strong>{logs.filter(l => l.threatLevel === 'SUSPICIOUS').length}</strong>
            </span>
            <span className="text-red-700">
              Malicious: <strong>{logs.filter(l => l.threatLevel === 'MALICIOUS').length}</strong>
            </span>
          </div>
        </Card>
      </div>

      {/* Threat Details Modal */}
      <ThreatDetailsModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        threatData={selectedThreat}
      />
    </DashboardLayout>
  );
};

export default LogViewer;
