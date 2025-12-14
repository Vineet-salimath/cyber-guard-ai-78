import { useEffect, useRef, useState } from 'react';
import { Activity, Radio, Wifi, WifiOff } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';

interface ExtensionData {
  url: string;
  threat_level: string;
  riskScore: number;
  timestamp: number;
  stats?: any;
}

interface RealTimeIntegrationProps {
  onNewScan?: (data: ExtensionData) => void;
  onStatsUpdate?: (stats: any) => void;
  onConnectionChange?: (connected: boolean) => void;
}

export const RealTimeExtensionIntegration = ({
  onNewScan,
  onStatsUpdate,
  onConnectionChange
}: RealTimeIntegrationProps) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [scanCount, setScanCount] = useState(0);
  const messageListenerRef = useRef<((event: MessageEvent) => void) | null>(null);
  const broadcastChannelRef = useRef<BroadcastChannel | null>(null);
  const heartbeatIntervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    console.log('🔌 [REALTIME] Initializing extension integration...');
    
    // Initialize all communication channels
    initializeExtensionBridge();
    initializeBroadcastChannel();
    initializeChromeStorageListener();
    startHeartbeat();
    
    // Check initial connection
    checkExtensionConnection();
    
    return () => {
      cleanup();
    };
  }, []);

  /**
   * Initialize window.postMessage listener for extension bridge
   */
  const initializeExtensionBridge = () => {
    const listener = (event: MessageEvent) => {
      // Security: Only accept messages from our extension
      if (event.data?.source !== 'malware-snipper-extension') {
        return;
      }

      console.log('📨 [REALTIME] Message received:', event.data.type);
      setLastUpdate(new Date());
      setIsConnected(true);
      onConnectionChange?.(true);

      // Handle different message types
      switch (event.data.type) {
        case 'NEW_SCAN_RESULT':
          handleNewScanResult(event.data.data);
          break;

        case 'STATS_UPDATE':
          handleStatsUpdate(event.data.data);
          break;

        case 'SCAN_STARTED':
          handleScanStarted(event.data.data);
          break;

        case 'EXTENSION_READY':
          console.log('✅ [REALTIME] Extension connection established');
          setIsConnected(true);
          onConnectionChange?.(true);
          break;

        case 'HISTORY_CLEARED':
          console.log('🗑️ [REALTIME] History cleared');
          break;

        default:
          console.log('❓ [REALTIME] Unknown message type:', event.data.type);
      }
    };

    messageListenerRef.current = listener;
    window.addEventListener('message', listener);
    console.log('✅ [REALTIME] Extension bridge listener active');
  };

  /**
   * Initialize BroadcastChannel for cross-tab communication
   */
  const initializeBroadcastChannel = () => {
    try {
      const channel = new BroadcastChannel('malware-snipper-updates');
      broadcastChannelRef.current = channel;

      channel.onmessage = (event) => {
        console.log('📡 [BROADCAST] Message received:', event.data.type);
        setLastUpdate(new Date());

        switch (event.data.type) {
          case 'scan_complete':
            handleNewScanResult(event.data.data);
            break;
          case 'traffic_batch_sent':
            console.log(`📤 [BROADCAST] Traffic batch: ${event.data.count} requests`);
            break;
          case 'heartbeat':
            setIsConnected(true);
            onConnectionChange?.(true);
            break;
        }
      };

      console.log('✅ [REALTIME] BroadcastChannel initialized');
    } catch (error) {
      console.warn('⚠️ [REALTIME] BroadcastChannel not available:', error);
    }
  };

  /**
   * Initialize Chrome storage listener for persistent data
   */
  const initializeChromeStorageListener = () => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === 'local') {
          console.log('💾 [STORAGE] Changes detected:', Object.keys(changes));
          setLastUpdate(new Date());
          setIsConnected(true);
          onConnectionChange?.(true);

          // Handle autoScanHistory updates
          if (changes.autoScanHistory) {
            const newHistory = changes.autoScanHistory.newValue || [];
            console.log(`📊 [STORAGE] Scan history updated: ${newHistory.length} items`);
            
            // Get the latest scan
            if (newHistory.length > 0) {
              const latestScan = newHistory[0];
              handleNewScanResult(latestScan);
            }
          }

          // Handle stats updates
          if (changes.realtimeStats) {
            const newStats = changes.realtimeStats.newValue;
            console.log('📊 [STORAGE] Stats updated:', newStats);
            handleStatsUpdate(newStats);
          }
        }
      });

      console.log('✅ [REALTIME] Chrome storage listener active');
    }
  };

  /**
   * Start heartbeat to keep connection alive
   */
  const startHeartbeat = () => {
    heartbeatIntervalRef.current = setInterval(() => {
      checkExtensionConnection();
    }, 5000); // Check every 5 seconds
  };

  /**
   * Check if extension is installed and responsive
   */
  const checkExtensionConnection = async () => {
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      try {
        const response = await chrome.runtime.sendMessage({ action: 'ping' });
        if (response?.pong) {
          setIsConnected(true);
          onConnectionChange?.(true);
        }
      } catch (error) {
        console.warn('⚠️ [REALTIME] Extension not responding');
        setIsConnected(false);
        onConnectionChange?.(false);
      }
    } else {
      // Check via storage as fallback
      if (typeof chrome !== 'undefined' && chrome.storage) {
        try {
          await chrome.storage.local.get(['autoScanHistory']);
          setIsConnected(true);
          onConnectionChange?.(true);
        } catch {
          setIsConnected(false);
          onConnectionChange?.(false);
        }
      }
    }
  };

  /**
   * Handle new scan result
   */
  const handleNewScanResult = (data: any) => {
    console.log('🚀 [REALTIME] New scan result:', data.url);
    setScanCount(prev => prev + 1);
    
    const formattedData: ExtensionData = {
      url: data.url,
      threat_level: data.threat_level || data.threatLevel,
      riskScore: data.riskScore || data.overall_risk_score || 0,
      timestamp: data.timestamp || Date.now(),
      stats: data.stats
    };

    onNewScan?.(formattedData);
  };

  /**
   * Handle stats update
   */
  const handleStatsUpdate = (stats: any) => {
    console.log('📊 [REALTIME] Stats updated:', stats);
    onStatsUpdate?.(stats);
  };

  /**
   * Handle scan started event
   */
  const handleScanStarted = (data: any) => {
    console.log('🔄 [REALTIME] Scan started:', data.url);
  };

  /**
   * Cleanup on unmount
   */
  const cleanup = () => {
    if (messageListenerRef.current) {
      window.removeEventListener('message', messageListenerRef.current);
    }
    if (broadcastChannelRef.current) {
      broadcastChannelRef.current.close();
    }
    if (heartbeatIntervalRef.current) {
      clearInterval(heartbeatIntervalRef.current);
    }
    console.log('🧹 [REALTIME] Cleanup complete');
  };

  return (
    <Card className="p-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border-blue-500/20">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {isConnected ? (
            <>
              <div className="relative">
                <Wifi className="h-5 w-5 text-green-400" />
                <span className="absolute -top-1 -right-1 flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                </span>
              </div>
              <div>
                <p className="text-sm font-semibold text-green-400">Extension Connected</p>
                <p className="text-xs text-gray-400">
                  Real-time monitoring active • {scanCount} scans captured
                </p>
              </div>
            </>
          ) : (
            <>
              <WifiOff className="h-5 w-5 text-red-400" />
              <div>
                <p className="text-sm font-semibold text-red-400">Extension Disconnected</p>
                <p className="text-xs text-gray-400">
                  Please install or enable the Malware Snipper extension
                </p>
              </div>
            </>
          )}
        </div>

        <div className="flex items-center gap-2">
          <Badge variant={isConnected ? "default" : "secondary"} className="gap-2">
            <Radio className={`h-3 w-3 ${isConnected ? 'animate-pulse' : ''}`} />
            {isConnected ? 'Live' : 'Offline'}
          </Badge>
          {lastUpdate && (
            <span className="text-xs text-gray-500">
              Updated {formatTimeAgo(lastUpdate)}
            </span>
          )}
        </div>
      </div>

      {/* Connection Instructions */}
      {!isConnected && (
        <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
          <p className="text-xs text-yellow-200 font-medium mb-2">
            📌 To enable real-time monitoring:
          </p>
          <ol className="text-xs text-gray-400 space-y-1 ml-4 list-decimal">
            <li>Open Chrome: <code className="text-blue-400">chrome://extensions/</code></li>
            <li>Enable "Developer mode" (top right)</li>
            <li>Click "Load unpacked"</li>
            <li>Select the <code className="text-blue-400">extension</code> folder</li>
            <li>Refresh this page</li>
          </ol>
        </div>
      )}
    </Card>
  );
};

/**
 * Format time ago helper
 */
function formatTimeAgo(date: Date): string {
  const seconds = Math.floor((new Date().getTime() - date.getTime()) / 1000);
  
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

export default RealTimeExtensionIntegration;
