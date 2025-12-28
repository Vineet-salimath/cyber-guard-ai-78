// useSafeLink - React hook for safe URL redirects
// Provides safe redirect functionality with notification UI

import { useState, useCallback } from 'react';

const SAFE_REDIRECT_ENDPOINT = process.env.REACT_APP_API_URL || 'http://localhost:5000';

interface URLCheckResult {
  verdict: 'clean' | 'malicious' | 'suspicious';
  action: 'allowed' | 'blocked' | 'warned';
  reason: string;
  risk_score: number;
  engine_detection_count: number;
  engine_total_count: number;
  threat_types: string[];
  scan_id: number;
}

interface UseSafeLinkOptions {
  userId?: string;
  onBlocked?: (result: URLCheckResult) => void;
  onWarning?: (result: URLCheckResult) => void;
  autoRedirect?: boolean;
}

export const useSafeLink = (options: UseSafeLinkOptions = {}) => {
  const {
    userId,
    onBlocked,
    onWarning,
    autoRedirect = true
  } = options;

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastWarning, setLastWarning] = useState<URLCheckResult | null>(null);

  const checkAndRedirect = useCallback(async (url: string, openNewTab = false) => {
    setIsLoading(true);
    setError(null);

    try {
      // Validate URL format
      try {
        new URL(url);
      } catch {
        setError('Invalid URL format');
        setIsLoading(false);
        return;
      }

      // Check with backend
      const response = await fetch(`${SAFE_REDIRECT_ENDPOINT}/api/safe/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: url,
          user_id: userId
        })
      });

      if (!response.ok) {
        throw new Error('Safety check failed');
      }

      const result: URLCheckResult = await response.json();

      // Handle verdict
      if (result.verdict === 'malicious') {
        onBlocked?.(result);
        setError(`Dangerous URL blocked (${result.reason})`);
        setIsLoading(false);
        return;
      }

      if (result.verdict === 'suspicious') {
        setLastWarning(result);
        onWarning?.(result);
        // For suspicious, allow user to proceed but show warning
        if (!autoRedirect) {
          setIsLoading(false);
          return;
        }
      }

      // Redirect (clean or after warning accepted)
      if (openNewTab) {
        window.open(url, '_blank');
      } else {
        window.location.href = url;
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMsg);
      console.error('[useSafeLink] Error:', err);
    } finally {
      setIsLoading(false);
    }
  }, [userId, onBlocked, onWarning, autoRedirect]);

  const handleSafeRedirect = useCallback((url: string) => {
    checkAndRedirect(url, false);
  }, [checkAndRedirect]);

  const handleSafeNewTab = useCallback((url: string) => {
    checkAndRedirect(url, true);
  }, [checkAndRedirect]);

  return {
    handleSafeRedirect,
    handleSafeNewTab,
    isLoading,
    error,
    lastWarning,
    clearError: () => setError(null),
    clearWarning: () => setLastWarning(null)
  };
};

// Component: SafeAnchor - Drop-in replacement for <a> tags
interface SafeAnchorProps extends React.AnchorHTMLAttributes<HTMLAnchorElement> {
  href: string;
  onBlockedUrl?: (result: URLCheckResult) => void;
  onWarningUrl?: (result: URLCheckResult) => void;
  userId?: string;
  children: React.ReactNode;
}

export const SafeAnchor: React.FC<SafeAnchorProps> = ({
  href,
  onBlockedUrl,
  onWarningUrl,
  userId,
  children,
  onClick,
  ...props
}) => {
  const { handleSafeRedirect, isLoading } = useSafeLink({
    userId,
    onBlocked: onBlockedUrl,
    onWarning: onWarningUrl
  });

  const handleClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    onClick?.(e);
    handleSafeRedirect(href);
  };

  // Check if URL is external
  const isExternal = href.startsWith('http://') || href.startsWith('https://');

  return (
    <a
      {...props}
      href={isExternal ? '#' : href}
      onClick={isExternal ? handleClick : onClick}
      style={{ opacity: isLoading ? 0.6 : 1, ...props.style }}
      title={isExternal ? props.title || 'Safe redirect' : props.title}
    >
      {children}
      {isLoading && <span> (checking...)</span>}
    </a>
  );
};

// Component: URL Warning Modal
interface URLWarningModalProps {
  result: URLCheckResult;
  onProceed: () => void;
  onCancel: () => void;
  targetUrl: string;
}

export const URLWarningModal: React.FC<URLWarningModalProps> = ({
  result,
  onProceed,
  onCancel,
  targetUrl
}) => {
  const domain = new URL(targetUrl).hostname;
  const engineInfo = result.engine_total_count > 0
    ? `${result.engine_detection_count}/${result.engine_total_count}`
    : 'Unknown';

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.5)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 9999
    }}>
      <div style={{
        backgroundColor: 'white',
        borderRadius: '8px',
        padding: '30px',
        maxWidth: '500px',
        boxShadow: '0 10px 40px rgba(0,0,0,0.3)'
      }}>
        <h2 style={{ color: '#FF8C00', marginBottom: '15px' }}>⚠️ Suspicious Site</h2>

        <p style={{ marginBottom: '20px', color: '#333', lineHeight: '1.6' }}>
          This site shows suspicious characteristics. Be cautious before proceeding.
        </p>

        <div style={{
          backgroundColor: '#f5f5f5',
          padding: '15px',
          borderRadius: '4px',
          marginBottom: '20px',
          borderLeft: '4px solid #FF8C00'
        }}>
          <div style={{ marginBottom: '10px' }}>
            <strong>Domain:</strong> {domain}
          </div>
          <div style={{ marginBottom: '10px' }}>
            <strong>Risk Level:</strong> {Math.round(result.risk_score)}/100
          </div>
          <div style={{ marginBottom: '10px' }}>
            <strong>Detection:</strong> {engineInfo} antivirus engines
          </div>
          <div>
            <strong>Reason:</strong> {result.reason}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
          <button
            onClick={onCancel}
            style={{
              padding: '10px 20px',
              backgroundColor: '#ddd',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            Cancel
          </button>
          <button
            onClick={onProceed}
            style={{
              padding: '10px 20px',
              backgroundColor: '#FF8C00',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 600
            }}
          >
            Proceed Anyway
          </button>
        </div>
      </div>
    </div>
  );
};

// Component: URL Scan History
interface UseScanHistoryOptions {
  userId?: string;
  limit?: number;
}

export const useScanHistory = (options: UseScanHistoryOptions = {}) => {
  const { userId, limit = 50 } = options;
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = useCallback(async () => {
    if (!userId) {
      setError('User ID required');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${SAFE_REDIRECT_ENDPOINT}/api/safe/scan-history?user_id=${userId}&limit=${limit}`
      );

      if (!response.ok) throw new Error('Failed to fetch scan history');

      const data = await response.json();
      setScans(data);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMsg);
    } finally {
      setLoading(false);
    }
  }, [userId, limit]);

  return { scans, loading, error, fetchHistory };
};

// Helper: Create safe redirect URL
export const createSafeRedirectURL = (targetUrl: string, userId?: string): string => {
  const params = new URLSearchParams();
  params.set('target', targetUrl);
  if (userId) params.set('user_id', userId);

  return `${SAFE_REDIRECT_ENDPOINT}/api/safe/redirect?${params.toString()}`;
};

// Helper: Encode URL for safe redirect
export const encodeSafeRedirectURL = (targetUrl: string): string => {
  try {
    new URL(targetUrl);
    return encodeURIComponent(targetUrl);
  } catch {
    throw new Error('Invalid URL');
  }
};
