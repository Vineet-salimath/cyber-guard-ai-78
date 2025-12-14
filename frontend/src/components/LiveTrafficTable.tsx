// ═══════════════════════════════════════════════════════════════════════════
// LIVE TRAFFIC TABLE - Real-time scan results display
// ═══════════════════════════════════════════════════════════════════════════

import { useState, useEffect } from 'react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { AlertTriangle, Shield, AlertCircle, Eye, Activity } from 'lucide-react';

interface ScanResult {
  id: string | number;
  url: string;
  timestamp: string | number;
  status: 'safe' | 'suspicious' | 'malicious' | 'benign' | 'phishing' | 'ransomware' | 'obfuscated_js';
  threatScore: number;
  classification?: string;
  indicators?: string[];
  method?: string;
}

interface LiveTrafficTableProps {
  scans: ScanResult[];
  onViewDetails?: (scan: ScanResult) => void;
}

export const LiveTrafficTable = ({ scans, onViewDetails }: LiveTrafficTableProps) => {
  const [displayScans, setDisplayScans] = useState<ScanResult[]>([]);
  const [newScanId, setNewScanId] = useState<string | number | null>(null);

  useEffect(() => {
    setDisplayScans(scans.slice(0, 50)); // Show last 50 scans
    
    // Highlight new scan
    if (scans.length > 0) {
      const latestScan = scans[0];
      setNewScanId(latestScan.id);
      
      // Remove highlight after 3 seconds
      setTimeout(() => {
        setNewScanId(null);
      }, 3000);
    }
  }, [scans]);

  const getThreatBadge = (scan: ScanResult) => {
    const classification = scan.classification || scan.status;
    const normalizedClassification = classification.toUpperCase();
    
    if (normalizedClassification === 'MALICIOUS' || normalizedClassification === 'RANSOMWARE') {
      return (
        <Badge variant="destructive" className="flex items-center gap-1">
          <AlertTriangle className="h-3 w-3" />
          {classification}
        </Badge>
      );
    }
    
    if (normalizedClassification === 'SUSPICIOUS' || normalizedClassification === 'PHISHING' || normalizedClassification === 'OBFUSCATED_JS') {
      return (
        <Badge variant="outline" className="border-orange-500 text-orange-700 flex items-center gap-1">
          <AlertCircle className="h-3 w-3" />
          {classification}
        </Badge>
      );
    }
    
    return (
      <Badge variant="outline" className="border-green-500 text-green-700 flex items-center gap-1">
        <Shield className="h-3 w-3" />
        {classification}
      </Badge>
    );
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-red-600 font-bold';
    if (score >= 40) return 'text-orange-600 font-semibold';
    return 'text-green-600';
  };

  const formatTimestamp = (timestamp: string | number) => {
    try {
      const date = typeof timestamp === 'number' ? new Date(timestamp) : new Date(timestamp);
      const now = Date.now();
      const diff = now - date.getTime();
      
      if (diff < 60000) return 'Just now';
      if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
      if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
      
      return date.toLocaleString();
    } catch {
      return 'Unknown';
    }
  };

  const truncateUrl = (url: string, maxLength: number = 60) => {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5" />
          Live Traffic Monitor
          <Badge variant="outline" className="ml-auto">
            {displayScans.length} recent scans
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[50px]">ID</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-center">Risk Score</TableHead>
                <TableHead>Method</TableHead>
                <TableHead>Timestamp</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {displayScans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                    <div className="flex flex-col items-center gap-2">
                      <Shield className="h-12 w-12 text-muted-foreground/50" />
                      <p>No scans yet. Visit a website to see real-time analysis.</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                displayScans.map((scan) => (
                  <TableRow
                    key={scan.id}
                    className={`
                      ${newScanId === scan.id ? 'bg-blue-50 animate-pulse' : ''}
                      hover:bg-muted/50 transition-colors
                    `}
                  >
                    <TableCell className="font-mono text-xs">{scan.id}</TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <span className="text-sm font-medium" title={scan.url}>
                          {truncateUrl(scan.url)}
                        </span>
                        {scan.indicators && scan.indicators.length > 0 && (
                          <div className="flex gap-1 flex-wrap">
                            {scan.indicators.slice(0, 2).map((indicator, idx) => (
                              <Badge key={idx} variant="outline" className="text-xs">
                                {indicator}
                              </Badge>
                            ))}
                            {scan.indicators.length > 2 && (
                              <Badge variant="outline" className="text-xs">
                                +{scan.indicators.length - 2} more
                              </Badge>
                            )}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>{getThreatBadge(scan)}</TableCell>
                    <TableCell className="text-center">
                      <span className={getRiskColor(scan.threatScore)}>
                        {scan.threatScore.toFixed(1)}%
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-xs">
                        {scan.method || 'GET'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatTimestamp(scan.timestamp)}
                    </TableCell>
                    <TableCell className="text-right">
                      <button
                        onClick={() => onViewDetails?.(scan)}
                        className="inline-flex items-center gap-1 text-xs text-blue-600 hover:text-blue-800 hover:underline"
                      >
                        <Eye className="h-3 w-3" />
                        Details
                      </button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
};

export default LiveTrafficTable;
