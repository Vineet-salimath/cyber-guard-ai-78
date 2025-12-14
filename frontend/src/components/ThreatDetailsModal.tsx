// THREAT DETAILS MODAL - Comprehensive threat analysis with 4 tabs
import { useState, useEffect } from 'react';
import { X, Shield, AlertTriangle, XCircle, Activity, FileText, Link as LinkIcon, Wrench } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface CVEData {
  id: string;
  description: string;
  cvss: {
    version: string;
    score: number;
    severity: string;
    vector: string;
    attackVector?: string;
    attackComplexity?: string;
    privilegesRequired?: string;
    userInteraction?: string;
    scope?: string;
    confidentialityImpact?: string;
    integrityImpact?: string;
    availabilityImpact?: string;
  };
  published: string;
  lastModified?: string;
  references: Array<{
    url: string;
    source: string;
    tags: string[];
  }>;
}

interface ThreatData {
  url: string;
  threat_level: string;
  overall_risk_score: number;
  stats: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
  };
  threat_names: string[];
  scan_date: string;
  mock?: boolean;
}

interface ThreatDetailsModalProps {
  isOpen: boolean;
  onClose: () => void;
  threatData: ThreatData | null;
}

const ThreatDetailsModal = ({ isOpen, onClose, threatData }: ThreatDetailsModalProps) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'cve' | 'remediation' | 'references'>('overview');
  const [cveData, setCveData] = useState<CVEData[]>([]);
  const [loadingCVE, setLoadingCVE] = useState(false);

  useEffect(() => {
    if (isOpen && threatData && threatData.threat_names.length > 0) {
      fetchCVEData();
    }
  }, [isOpen, threatData]);

  const fetchCVEData = async () => {
    if (!threatData) return;
    
    setLoadingCVE(true);
    try {
      const response = await fetch('http://localhost:5000/get-cve-details', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          threat_names: threatData.threat_names,
          cve_ids: []
        })
      });
      
      const data = await response.json();
      setCveData(data.cves || []);
    } catch (error) {
      console.error('Error fetching CVE data:', error);
      setCveData([]);
    } finally {
      setLoadingCVE(false);
    }
  };

  if (!isOpen || !threatData) return null;

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'SAFE':
        return 'text-green-600 bg-green-100 border-green-200';
      case 'SUSPICIOUS':
        return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'MALICIOUS':
        return 'text-red-600 bg-red-100 border-red-200';
      default:
        return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'SAFE':
        return <Shield className="w-6 h-6 text-green-600" />;
      case 'SUSPICIOUS':
        return <AlertTriangle className="w-6 h-6 text-yellow-600" />;
      case 'MALICIOUS':
        return <XCircle className="w-6 h-6 text-red-600" />;
      default:
        return <Activity className="w-6 h-6 text-gray-600" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-600 text-white';
      case 'HIGH':
        return 'bg-orange-600 text-white';
      case 'MEDIUM':
        return 'bg-yellow-600 text-white';
      case 'LOW':
        return 'bg-blue-600 text-white';
      default:
        return 'bg-gray-600 text-white';
    }
  };

  const getRemediationSteps = (threatLevel: string, threatNames: string[]) => {
    const isMalware = threatNames.some(t => t.toLowerCase().includes('malware') || t.toLowerCase().includes('trojan'));
    const isPhishing = threatNames.some(t => t.toLowerCase().includes('phishing'));
    const isPUP = threatNames.some(t => t.toLowerCase().includes('pup') || t.toLowerCase().includes('adware'));
    
    if (threatLevel === 'MALICIOUS') {
      if (isPhishing) {
        return [
          'Do NOT enter any credentials or personal information on this website',
          'Close the browser tab immediately',
          'Clear browser cache and cookies (Settings → Privacy → Clear browsing data)',
          'Run a full system antivirus scan',
          'Change passwords if you entered any credentials',
          'Enable two-factor authentication (2FA) on affected accounts',
          'Report the phishing site to Google Safe Browsing and your antivirus provider',
          'Monitor your financial accounts for suspicious activity'
        ];
      } else if (isMalware) {
        return [
          'Close the browser and disconnect from the internet immediately',
          'Boot system in Safe Mode',
          'Run a comprehensive antivirus scan with updated definitions',
          'Use anti-malware tools (Malwarebytes, HitmanPro)',
          'Check browser extensions and remove suspicious ones',
          'Reset browser settings to default',
          'Change all important passwords from a clean device',
          'Consider professional malware removal if infection persists'
        ];
      }
    } else if (threatLevel === 'SUSPICIOUS') {
      if (isPUP) {
        return [
          'Avoid downloading anything from this website',
          'Check installed programs for unwanted software',
          'Uninstall suspicious programs via Control Panel',
          'Reset browser homepage and search engine settings',
          'Remove suspicious browser extensions',
          'Clear browser cache and cookies',
          'Run a quick antivirus scan as a precaution'
        ];
      }
    }
    
    // Default safe remediation
    return [
      'This site appears safe, but exercise caution',
      'Verify the URL is correct and uses HTTPS',
      'Keep your browser and antivirus software updated',
      'Avoid clicking suspicious links or downloading unexpected files',
      'Use strong, unique passwords for each website'
    ];
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'cve', label: 'CVE/CVSS', icon: FileText },
    { id: 'remediation', label: 'Remediation', icon: Wrench },
    { id: 'references', label: 'References', icon: LinkIcon }
  ];

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          className="bg-white rounded-lg shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="bg-gradient-to-r from-purple-600 to-indigo-600 text-white p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {getThreatIcon(threatData.threat_level)}
                <div>
                  <h2 className="text-2xl font-bold">Threat Analysis Report</h2>
                  <p className="text-purple-100 text-sm mt-1">{threatData.url}</p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="p-2 hover:bg-white hover:bg-opacity-20 rounded-full transition"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            
            {/* Threat Level Badge */}
            <div className="mt-4 flex items-center gap-4">
              <span className={`px-4 py-2 rounded-full text-sm font-bold border-2 ${getThreatColor(threatData.threat_level)}`}>
                {threatData.threat_level}
              </span>
              <div className="flex-1 bg-white bg-opacity-20 rounded-full p-1">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span>Risk Score</span>
                  <span className="font-bold">{threatData.overall_risk_score}/100</span>
                </div>
                <div className="w-full bg-white bg-opacity-30 rounded-full h-2">
                  <div
                    className={`h-full rounded-full ${
                      threatData.overall_risk_score > 70 ? 'bg-red-500' :
                      threatData.overall_risk_score > 30 ? 'bg-yellow-500' :
                      'bg-green-500'
                    }`}
                    style={{ width: `${threatData.overall_risk_score}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="border-b">
            <div className="flex">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex-1 px-4 py-3 flex items-center justify-center gap-2 font-medium transition ${
                    activeTab === tab.id
                      ? 'text-purple-600 border-b-2 border-purple-600 bg-purple-50'
                      : 'text-gray-600 hover:bg-gray-50'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Tab Content */}
          <div className="p-6 overflow-y-auto max-h-[50vh]">
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Detection Statistics */}
                <div>
                  <h3 className="text-lg font-semibold mb-4">Detection Statistics</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                      <div className="text-red-600 text-2xl font-bold">{threatData.stats.malicious}</div>
                      <div className="text-red-700 text-sm">Malicious</div>
                    </div>
                    <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                      <div className="text-yellow-600 text-2xl font-bold">{threatData.stats.suspicious}</div>
                      <div className="text-yellow-700 text-sm">Suspicious</div>
                    </div>
                    <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                      <div className="text-green-600 text-2xl font-bold">{threatData.stats.harmless}</div>
                      <div className="text-green-700 text-sm">Harmless</div>
                    </div>
                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                      <div className="text-gray-600 text-2xl font-bold">{threatData.stats.undetected}</div>
                      <div className="text-gray-700 text-sm">Undetected</div>
                    </div>
                  </div>
                </div>

                {/* Detected Threats */}
                {threatData.threat_names.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold mb-3">Detected Threats</h3>
                    <div className="space-y-2">
                      {threatData.threat_names.map((threat, index) => (
                        <div key={index} className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-center gap-2">
                          <XCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
                          <span className="text-red-900 font-mono text-sm">{threat}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Scan Information */}
                <div className="bg-gray-50 rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-gray-700 mb-2">Scan Information</h3>
                  <div className="space-y-1 text-sm text-gray-600">
                    <div>Scan Date: {new Date(threatData.scan_date).toLocaleString()}</div>
                    <div>Total Engines: {Object.values(threatData.stats).reduce((a, b) => a + b, 0)}</div>
                    {threatData.mock && <div className="text-orange-600 font-medium">⚠️ Mock Data (API key not configured)</div>}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'cve' && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">CVE/CVSS Vulnerability Data</h3>
                
                {loadingCVE ? (
                  <div className="text-center py-12">
                    <div className="w-12 h-12 border-4 border-purple-600 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
                    <p className="text-gray-600">Fetching CVE data from NVD...</p>
                  </div>
                ) : cveData.length > 0 ? (
                  cveData.map((cve, index) => (
                    <div key={index} className="border rounded-lg p-4 space-y-3">
                      <div className="flex items-start justify-between">
                        <div>
                          <h4 className="font-semibold text-lg">{cve.id}</h4>
                          <p className="text-sm text-gray-600 mt-1">{cve.description}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${getSeverityColor(cve.cvss.severity)}`}>
                          {cve.cvss.severity}
                        </span>
                      </div>
                      
                      <div className="bg-gray-50 rounded p-3 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">CVSS Score:</span>
                          <span className="text-xl font-bold">{cve.cvss.score}/10</span>
                        </div>
                        <div className="text-xs text-gray-600">
                          <div>Vector: {cve.cvss.vector}</div>
                          {cve.cvss.attackVector && <div>Attack Vector: {cve.cvss.attackVector}</div>}
                          {cve.cvss.userInteraction && <div>User Interaction: {cve.cvss.userInteraction}</div>}
                        </div>
                      </div>
                      
                      {cve.published && (
                        <div className="text-xs text-gray-500">
                          Published: {new Date(cve.published).toLocaleDateString()}
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <div className="text-center py-12 text-gray-500">
                    <FileText className="w-16 h-16 mx-auto mb-4 opacity-20" />
                    <p>No CVE data available for this threat</p>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'remediation' && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Remediation Steps</h3>
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
                  <p className="text-blue-900 text-sm">
                    Follow these steps carefully to protect your system and data.
                  </p>
                </div>
                <div className="space-y-3">
                  {getRemediationSteps(threatData.threat_level, threatData.threat_names).map((step, index) => (
                    <div key={index} className="flex gap-3">
                      <div className="flex-shrink-0 w-6 h-6 rounded-full bg-purple-600 text-white flex items-center justify-center text-sm font-bold">
                        {index + 1}
                      </div>
                      <p className="text-gray-700 flex-1">{step}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'references' && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">External References</h3>
                
                {cveData.some(cve => cve.references && cve.references.length > 0) ? (
                  <div className="space-y-3">
                    {cveData.flatMap(cve => cve.references || []).map((ref, index) => (
                      <a
                        key={index}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block border rounded-lg p-3 hover:bg-gray-50 transition"
                      >
                        <div className="flex items-start gap-2">
                          <LinkIcon className="w-4 h-4 text-blue-600 mt-1 flex-shrink-0" />
                          <div className="flex-1">
                            <div className="text-blue-600 hover:underline break-all">{ref.url}</div>
                            {ref.source && <div className="text-xs text-gray-500 mt-1">Source: {ref.source}</div>}
                            {ref.tags && ref.tags.length > 0 && (
                              <div className="flex gap-1 mt-2 flex-wrap">
                                {ref.tags.map((tag, i) => (
                                  <span key={i} className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded">
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </a>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12 text-gray-500">
                    <LinkIcon className="w-16 h-16 mx-auto mb-4 opacity-20" />
                    <p>No external references available</p>
                  </div>
                )}
                
                {/* Additional Resources */}
                <div className="mt-6 bg-gray-50 rounded-lg p-4">
                  <h4 className="font-semibold mb-3">Additional Resources</h4>
                  <div className="space-y-2 text-sm">
                    <a href="https://www.virustotal.com/" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline block">
                      VirusTotal - Analyze suspicious files and URLs
                    </a>
                    <a href="https://nvd.nist.gov/" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline block">
                      National Vulnerability Database (NVD)
                    </a>
                    <a href="https://www.cisa.gov/cybersecurity" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline block">
                      CISA Cybersecurity Resources
                    </a>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="border-t p-4 bg-gray-50 flex justify-end gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 transition"
            >
              Close
            </button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default ThreatDetailsModal;
