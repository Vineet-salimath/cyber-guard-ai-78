// SafeLinkExample.tsx - Example React components using safe links

import React, { useState, useEffect } from 'react';
import { SafeAnchor, useSafeLink, useScanHistory, URLWarningModal, URLCheckResult } from '../hooks/useSafeLink';

// ═══════════════════════════════════════════════════════════════════════════
// Example 1: Simple safe link replacement
// ═══════════════════════════════════════════════════════════════════════════

export const SimpleSafeLinkExample: React.FC = () => {
  return (
    <div>
      <h3>Safe Links Example</h3>

      {/* Before: Regular anchor */}
      {/* <a href="https://example.com">Click here</a> */}

      {/* After: Safe anchor with automatic checking */}
      <SafeAnchor
        href="https://example.com"
        userId="user123"
      >
        Click here (safe)
      </SafeAnchor>

      {/* With callbacks for blocked URLs */}
      <SafeAnchor
        href="https://suspicious-site.com"
        userId="user123"
        onBlockedUrl={(result) => {
          alert(`This URL is blocked: ${result.reason}`);
        }}
        onWarningUrl={(result) => {
          console.log('User accessing suspicious site:', result);
        }}
      >
        Suspicious link
      </SafeAnchor>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════
// Example 2: Manual link handling with warning modal
// ═══════════════════════════════════════════════════════════════════════════

export const AdvancedSafeLinkExample: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [warning, setWarning] = useState<{ result: URLCheckResult; url: string } | null>(null);
  const { handleSafeRedirect, isLoading, error } = useSafeLink({
    userId: 'user123',
    autoRedirect: false, // Don't auto-redirect, let us handle warnings
    onWarning: (result) => {
      setWarning({ result, url: targetUrl });
    },
    onBlocked: (result) => {
      alert(`URL blocked: ${result.reason}`);
    }
  });

  const handleProceed = () => {
    setWarning(null);
    window.location.href = targetUrl;
  };

  const handleCancel = () => {
    setWarning(null);
    setTargetUrl('');
  };

  return (
    <div>
      <input
        type="url"
        placeholder="Enter URL"
        value={targetUrl}
        onChange={(e) => setTargetUrl(e.target.value)}
      />

      <button
        onClick={() => handleSafeRedirect(targetUrl)}
        disabled={isLoading || !targetUrl}
      >
        {isLoading ? 'Checking...' : 'Open URL'}
      </button>

      {error && <div style={{ color: 'red' }}>{error}</div>}

      {warning && (
        <URLWarningModal
          result={warning.result}
          targetUrl={warning.url}
          onProceed={handleProceed}
          onCancel={handleCancel}
        />
      )}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════
// Example 3: Scan history viewer
// ═══════════════════════════════════════════════════════════════════════════

interface ScanRecord {
  id: number;
  target_url: string;
  verdict: string;
  action: string;
  reason: string;
  risk_score: number;
  engine_detection_count: number;
  engine_total_count: number;
  created_at: string;
}

export const ScanHistoryViewer: React.FC<{ userId: string }> = ({ userId }) => {
  const { scans, loading, error, fetchHistory } = useScanHistory({
    userId,
    limit: 20
  });

  useEffect(() => {
    fetchHistory();
    // Refresh every 30 seconds
    const interval = setInterval(fetchHistory, 30000);
    return () => clearInterval(interval);
  }, [fetchHistory]);

  if (loading) return <div>Loading scan history...</div>;
  if (error) return <div style={{ color: 'red' }}>Error: {error}</div>;

  return (
    <div style={{ marginTop: '20px' }}>
      <h3>Your Recent URL Scans</h3>
      {scans.length === 0 ? (
        <p>No scans yet</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ backgroundColor: '#f0f0f0' }}>
              <th style={{ padding: '10px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>URL</th>
              <th style={{ padding: '10px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>Verdict</th>
              <th style={{ padding: '10px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>Risk</th>
              <th style={{ padding: '10px', textAlign: 'left', borderBottom: '1px solid #ddd' }}>Date</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan: ScanRecord) => (
              <tr key={scan.id} style={{ borderBottom: '1px solid #eee' }}>
                <td style={{ padding: '10px' }}>
                  <a href="#" onClick={(e) => {
                    e.preventDefault();
                    const domain = new URL(scan.target_url).hostname;
                    alert(`Domain: ${domain}\nFull URL: ${scan.target_url}`);
                  }}>
                    {new URL(scan.target_url).hostname}
                  </a>
                </td>
                <td style={{ padding: '10px' }}>
                  <span style={{
                    padding: '4px 8px',
                    borderRadius: '4px',
                    backgroundColor: scan.verdict === 'malicious' ? '#8B0000' : '#FF8C00',
                    color: 'white',
                    fontSize: '12px'
                  }}>
                    {scan.verdict.toUpperCase()}
                  </span>
                </td>
                <td style={{ padding: '10px' }}>
                  {Math.round(scan.risk_score)}/100
                </td>
                <td style={{ padding: '10px' }}>
                  {new Date(scan.created_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════
// Example 4: Link converter helper - wrap all external links
// ═══════════════════════════════════════════════════════════════════════════

interface BlogPostProps {
  content: string;
  userId: string;
}

export const BlogPostWithSafeLinks: React.FC<BlogPostProps> = ({ content, userId }) => {
  // In practice, you'd parse the HTML and replace <a> tags
  // This is a simplified example

  return (
    <div className="blog-post">
      {/* Convert all external links in content to SafeAnchor */}
      {/* This could be done with a library like DOMPurify + custom processing */}
      <p>
        Check out{' '}
        <SafeAnchor href="https://example.com/article" userId={userId}>
          this article
        </SafeAnchor>
        {' '}for more info.
      </p>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════
// Example 5: Admin dashboard - view all blocked URLs
// ═══════════════════════════════════════════════════════════════════════════

export const AdminBlockedURLsDashboard: React.FC = () => {
  const [blockedUrls, setBlockedUrls] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchBlockedUrls = async () => {
      try {
        const response = await fetch('http://localhost:5000/api/safe/blocked-urls?limit=100');
        const data = await response.json();
        setBlockedUrls(data);
      } catch (error) {
        console.error('Error fetching blocked URLs:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchBlockedUrls();
    // Refresh every minute
    const interval = setInterval(fetchBlockedUrls, 60000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div>Loading...</div>;

  return (
    <div style={{ padding: '20px' }}>
      <h2>Blocked URLs (Admin Dashboard)</h2>
      <div style={{ marginBottom: '20px' }}>
        <strong>Total Blocked Today:</strong> {blockedUrls.length}
      </div>

      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ backgroundColor: '#333', color: 'white' }}>
            <th style={{ padding: '12px', textAlign: 'left' }}>User</th>
            <th style={{ padding: '12px', textAlign: 'left' }}>URL</th>
            <th style={{ padding: '12px', textAlign: 'left' }}>Verdict</th>
            <th style={{ padding: '12px', textAlign: 'left' }}>Risk</th>
            <th style={{ padding: '12px', textAlign: 'left' }}>Engines</th>
            <th style={{ padding: '12px', textAlign: 'left' }}>Time</th>
          </tr>
        </thead>
        <tbody>
          {blockedUrls.map((item, idx) => (
            <tr key={idx} style={{ borderBottom: '1px solid #ddd' }}>
              <td style={{ padding: '12px' }}>{item.user_id || 'Unknown'}</td>
              <td style={{ padding: '12px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {new URL(item.target_url).hostname}
              </td>
              <td style={{ padding: '12px' }}>
                <span style={{
                  padding: '4px 8px',
                  borderRadius: '4px',
                  backgroundColor: item.verdict === 'malicious' ? '#8B0000' : '#FF8C00',
                  color: 'white',
                  fontSize: '12px'
                }}>
                  {item.verdict}
                </span>
              </td>
              <td style={{ padding: '12px' }}>{Math.round(item.risk_score)}</td>
              <td style={{ padding: '12px' }}>
                {item.engine_detection_count}/{item.engine_total_count}
              </td>
              <td style={{ padding: '12px' }}>
                {new Date(item.created_at).toLocaleTimeString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
