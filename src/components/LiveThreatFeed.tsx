// LIVE THREAT FEED - Shows latest scanned URLs with color-coded threat levels
// Updates in real-time with animations

import { useEffect, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { ScrollArea } from './ui/scroll-area';
import { Shield, AlertTriangle, AlertOctagon, Clock, ExternalLink, Activity } from 'lucide-react';

interface ScanResult {
  url: string;
  risk?: 'benign' | 'suspicious' | 'malicious' | string; // Allow string for flexibility
  status?: 'benign' | 'suspicious' | 'malicious' | 'safe'; // Also support status field
  score?: number;
  threatScore?: number; // Also support threatScore field
  ml_prediction?: string;
  timestamp: string;
}

interface LiveThreatFeedProps {
  scans: ScanResult[];
  maxItems?: number;
}

const LiveThreatFeed = ({ scans, maxItems = 20 }: LiveThreatFeedProps) => {
  const feedRef = useRef<HTMLDivElement>(null);
  const prevLengthRef = useRef(scans.length);

  useEffect(() => {
    // Scroll to top when new scan arrives
    if (scans.length > prevLengthRef.current && feedRef.current) {
      feedRef.current.scrollTo({ top: 0, behavior: 'smooth' });
      
      // Flash animation
      const firstItem = feedRef.current.querySelector('.scan-item:first-child');
      if (firstItem) {
        firstItem.classList.add('animate-pulse', 'bg-blue-50', 'dark:bg-blue-900/20');
        setTimeout(() => {
          firstItem.classList.remove('animate-pulse', 'bg-blue-50', 'dark:bg-blue-900/20');
        }, 1000);
      }
    }
    prevLengthRef.current = scans.length;
  }, [scans]);

  const getThreatIcon = (scan: ScanResult) => {
    const risk = scan.risk || scan.status || 'benign';
    switch (risk) {
      case 'benign':
      case 'safe':
        return <Shield className="h-4 w-4 text-green-500" />;
      case 'suspicious':
        return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      case 'malicious':
        return <AlertOctagon className="h-4 w-4 text-red-500" />;
      default:
        return <Shield className="h-4 w-4 text-gray-500" />;
    }
  };

  const getThreatBadge = (scan: ScanResult) => {
    const risk = scan.risk || scan.status || 'benign';
    switch (risk) {
      case 'benign':
      case 'safe':
        return <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">Safe</Badge>;
      case 'suspicious':
        return <Badge variant="outline" className="bg-orange-50 text-orange-700 border-orange-200">Suspicious</Badge>;
      case 'malicious':
        return <Badge variant="destructive">Malicious</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const getRiskColor = (scan: ScanResult) => {
    const risk = scan.risk || scan.status || 'benign';
    switch (risk) {
      case 'benign':
      case 'safe':
        return 'border-l-green-500';
      case 'suspicious':
        return 'border-l-orange-500';
      case 'malicious':
        return 'border-l-red-500';
      default:
        return 'border-l-gray-300';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffSecs = Math.floor(diffMs / 1000);
      const diffMins = Math.floor(diffSecs / 60);
      const diffHours = Math.floor(diffMins / 60);

      if (diffSecs < 60) return `${diffSecs}s ago`;
      if (diffMins < 60) return `${diffMins}m ago`;
      if (diffHours < 24) return `${diffHours}h ago`;
      return date.toLocaleDateString();
    } catch {
      return timestamp;
    }
  };

  const truncateUrl = (url: string, maxLength = 50) => {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
  };

  if (scans.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Live Threat Feed
          </CardTitle>
          <CardDescription>Real-time scan results appear here</CardDescription>
        </CardHeader>
        <CardContent className="h-96 flex items-center justify-center">
          <div className="text-center">
            <Activity className="h-12 w-12 text-gray-300 mx-auto mb-3 animate-pulse" />
            <p className="text-gray-400 text-sm">Waiting for scans...</p>
            <p className="text-gray-300 text-xs mt-1">Visit any website to see results</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const displayScans = scans.slice(0, maxItems);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5 animate-pulse text-blue-500" />
          Live Threat Feed
          <Badge variant="outline" className="ml-auto">
            {scans.length} scans
          </Badge>
        </CardTitle>
        <CardDescription>
          Latest security scan results • Updates in real-time
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[500px] pr-4" ref={feedRef}>
          <div className="space-y-3">
            {displayScans.map((scan, index) => {
              const risk = scan.risk || scan.status || 'benign';
              const score = scan.score || scan.threatScore || 0;
              
              return (
              <div
                key={`${scan.url}-${scan.timestamp}-${index}`}
                className={`scan-item p-4 rounded-lg border-l-4 ${getRiskColor(scan)} bg-white dark:bg-gray-800 shadow-sm hover:shadow-md transition-all duration-200`}
              >
                {/* Header */}
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    {getThreatIcon(scan)}
                    <a
                      href={scan.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm font-medium text-gray-900 dark:text-white hover:text-blue-600 dark:hover:text-blue-400 truncate flex items-center gap-1"
                      title={scan.url}
                    >
                      {truncateUrl(scan.url)}
                      <ExternalLink className="h-3 w-3 flex-shrink-0" />
                    </a>
                  </div>
                  {getThreatBadge(scan)}
                </div>

                {/* Details */}
                <div className="flex items-center gap-4 text-xs text-gray-600 dark:text-gray-400 mt-2">
                  <div className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    <span>{formatTimestamp(scan.timestamp)}</span>
                  </div>
                  
                  <div className="flex items-center gap-1">
                    <span className="font-semibold">Risk:</span>
                    <span className={`font-bold ${
                      score >= 70 ? 'text-red-600' :
                      score >= 40 ? 'text-orange-600' :
                      'text-green-600'
                    }`}>
                      {score.toFixed(1)}/100
                    </span>
                  </div>

                  {scan.ml_prediction && (
                    <div className="flex items-center gap-1">
                      <span className="font-semibold">ML:</span>
                      <Badge variant="outline" className="text-xs py-0 px-1 h-5">
                        {scan.ml_prediction}
                      </Badge>
                    </div>
                  )}
                </div>

                {/* Progress bar for risk score */}
                <div className="mt-3 h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      score >= 70 ? 'bg-red-500' :
                      score >= 40 ? 'bg-orange-500' :
                      'bg-green-500'
                    }`}
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>
            )}
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default LiveThreatFeed;
