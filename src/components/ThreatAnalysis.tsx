// THREAT ANALYSIS - Top malicious domains and breakdown percentages
import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, XCircle, BarChart3, TrendingUp } from 'lucide-react';
import DashboardLayout from '@/components/DashboardLayout';
import { Card } from '@/components/ui/card';

interface ThreatStats {
  totalScans: number;
  safe: number;
  suspicious: number;
  malicious: number;
  topMaliciousDomains: {
    domain: string;
    count: number;
    riskScore: number;
  }[];
  threatDistribution: {
    category: string;
    percentage: number;
    count: number;
  }[];
}

const ThreatAnalysis = () => {
  const [stats, setStats] = useState<ThreatStats>({
    totalScans: 0,
    safe: 0,
    suspicious: 0,
    malicious: 0,
    topMaliciousDomains: [],
    threatDistribution: []
  });

  useEffect(() => {
    loadThreatData();

    // Update every 5 seconds
    const interval = setInterval(() => {
      loadThreatData();
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const loadThreatData = () => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['autoScanHistory'], (result) => {
        const history = result.autoScanHistory || [];
        
        // Calculate stats
        const totalScans = history.length;
        const safe = history.filter((s: any) => s.threatLevel === 'SAFE').length;
        const suspicious = history.filter((s: any) => s.threatLevel === 'SUSPICIOUS').length;
        const malicious = history.filter((s: any) => s.threatLevel === 'MALICIOUS').length;

        // Extract domains and count occurrences
        const domainMap = new Map<string, { count: number; totalRisk: number }>();
        
        history
          .filter((scan: any) => scan.threatLevel === 'MALICIOUS')
          .forEach((scan: any) => {
            try {
              const domain = new URL(scan.url).hostname;
              const existing = domainMap.get(domain) || { count: 0, totalRisk: 0 };
              domainMap.set(domain, {
                count: existing.count + 1,
                totalRisk: existing.totalRisk + (scan.riskScore || 0)
              });
            } catch (e) {
              // Invalid URL, skip
            }
          });

        // Convert to array and sort by count
        const topMaliciousDomains = Array.from(domainMap.entries())
          .map(([domain, data]) => ({
            domain,
            count: data.count,
            riskScore: Math.round(data.totalRisk / data.count)
          }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 10);

        // Threat distribution
        const threatDistribution = [
          {
            category: 'Safe',
            percentage: totalScans > 0 ? Math.round((safe / totalScans) * 100) : 0,
            count: safe
          },
          {
            category: 'Suspicious',
            percentage: totalScans > 0 ? Math.round((suspicious / totalScans) * 100) : 0,
            count: suspicious
          },
          {
            category: 'Malicious',
            percentage: totalScans > 0 ? Math.round((malicious / totalScans) * 100) : 0,
            count: malicious
          }
        ];

        setStats({
          totalScans,
          safe,
          suspicious,
          malicious,
          topMaliciousDomains,
          threatDistribution
        });
      });
    } else {
      // Mock data for testing
      setStats({
        totalScans: 150,
        safe: 110,
        suspicious: 25,
        malicious: 15,
        topMaliciousDomains: [
          { domain: 'malware-site.xyz', count: 5, riskScore: 92 },
          { domain: 'phishing-bank.com', count: 4, riskScore: 88 },
          { domain: 'fake-login.net', count: 3, riskScore: 85 }
        ],
        threatDistribution: [
          { category: 'Safe', percentage: 73, count: 110 },
          { category: 'Suspicious', percentage: 17, count: 25 },
          { category: 'Malicious', percentage: 10, count: 15 }
        ]
      });
    }
  };

  const getPercentageColor = (category: string) => {
    switch (category) {
      case 'Safe':
        return 'bg-green-500';
      case 'Suspicious':
        return 'bg-yellow-500';
      case 'Malicious':
        return 'bg-red-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'Safe':
        return <Shield className="w-5 h-5 text-green-600" />;
      case 'Suspicious':
        return <AlertTriangle className="w-5 h-5 text-yellow-600" />;
      case 'Malicious':
        return <XCircle className="w-5 h-5 text-red-600" />;
      default:
        return null;
    }
  };

  return (
    <DashboardLayout>
      <div className="p-6 lg:p-8 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Threat Analytics</h1>
            <p className="text-muted-foreground">
              Detailed breakdown of detected threats and malicious domains
            </p>
          </div>
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <BarChart3 className="w-5 h-5" />
            <span>{stats.totalScans} Total Scans</span>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid gap-4 md:grid-cols-3">
          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Safe Sites</p>
                <p className="text-3xl font-bold text-green-600">{stats.safe}</p>
              </div>
              <Shield className="w-12 h-12 text-green-600 opacity-20" />
            </div>
            <div className="mt-2 text-sm text-gray-600">
              {stats.totalScans > 0 ? Math.round((stats.safe / stats.totalScans) * 100) : 0}% of total
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Suspicious</p>
                <p className="text-3xl font-bold text-yellow-600">{stats.suspicious}</p>
              </div>
              <AlertTriangle className="w-12 h-12 text-yellow-600 opacity-20" />
            </div>
            <div className="mt-2 text-sm text-gray-600">
              {stats.totalScans > 0 ? Math.round((stats.suspicious / stats.totalScans) * 100) : 0}% of total
            </div>
          </Card>

          <Card className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Malicious</p>
                <p className="text-3xl font-bold text-red-600">{stats.malicious}</p>
              </div>
              <XCircle className="w-12 h-12 text-red-600 opacity-20" />
            </div>
            <div className="mt-2 text-sm text-gray-600">
              {stats.totalScans > 0 ? Math.round((stats.malicious / stats.totalScans) * 100) : 0}% of total
            </div>
          </Card>
        </div>

        {/* Threat Distribution */}
        <Card className="p-6">
          <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Threat Distribution
          </h2>
          
          <div className="space-y-4">
            {stats.threatDistribution.map((dist) => (
              <div key={dist.category} className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {getCategoryIcon(dist.category)}
                    <span className="font-medium">{dist.category}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-sm text-gray-600">{dist.count} scans</span>
                    <span className="font-semibold">{dist.percentage}%</span>
                  </div>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${getPercentageColor(dist.category)}`}
                    style={{ width: `${dist.percentage}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Top Malicious Domains */}
        <Card className="p-6">
          <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
            <XCircle className="w-5 h-5 text-red-600" />
            Top Malicious Domains
          </h2>

          {stats.topMaliciousDomains.length === 0 ? (
            <div className="text-center py-12 text-gray-500">
              <Shield className="w-16 h-16 mx-auto mb-4 opacity-20" />
              <p className="text-lg font-medium">No malicious domains detected</p>
              <p className="text-sm">Your browsing is secure!</p>
            </div>
          ) : (
            <div className="space-y-3">
              {stats.topMaliciousDomains.map((domain, index) => (
                <div
                  key={domain.domain}
                  className="flex items-center justify-between p-4 bg-red-50 rounded-lg border border-red-100"
                >
                  <div className="flex items-center gap-4">
                    <div className="flex items-center justify-center w-8 h-8 rounded-full bg-red-600 text-white font-bold">
                      {index + 1}
                    </div>
                    <div>
                      <p className="font-mono font-medium text-red-900">{domain.domain}</p>
                      <p className="text-sm text-red-700">Risk Score: {domain.riskScore}/100</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-2xl font-bold text-red-600">{domain.count}</p>
                    <p className="text-xs text-red-700">detections</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Risk Assessment */}
        <Card className="p-6 bg-gradient-to-r from-blue-50 to-purple-50 border-blue-200">
          <h3 className="font-semibold mb-2">Overall Risk Assessment</h3>
          <p className="text-sm text-gray-700">
            {stats.malicious > 10 
              ? '⚠️ High risk detected - Multiple malicious sites encountered. Review your browsing habits.'
              : stats.suspicious > 5
              ? '⚡ Moderate risk - Some suspicious activity detected. Stay vigilant.'
              : '✅ Low risk - Your browsing appears safe. Keep up the good security practices!'}
          </p>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default ThreatAnalysis;
