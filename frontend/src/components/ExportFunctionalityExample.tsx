// Integration Example - How to use DownloadDropdown with ScanTable
// This file demonstrates the complete implementation of the export functionality

import React, { useState } from 'react';
import ScanTable from '@/components/ScanTable';
import { URLScanCard } from '@/components/URLScanCard';
import type { ScanData } from '@/services/reportGenerator';

// Example scan data
const exampleScans: ScanData[] = [
  {
    id: '1',
    url: 'https://malicious-site.com',
    timestamp: new Date().toISOString(),
    status: 'malicious',
    threatScore: 89,
    classification: 'Trojan',
    method: 'GET',
    indicators: ['suspicious_js_obfuscation', 'credential_stealer', 'malware_signature_detected'],
    analysis: {
      ml_prediction: 'Malicious',
      ml_confidence: 0.95,
      ml_risk_score: 89,
      virustotal_threat_level: 'DANGEROUS',
      virustotal_risk_score: 87,
      javascript_risk_score: 92,
      pattern_risk_score: 85,
      page_risk_score: 90,
    },
    details: {
      has_obfuscated_js: true,
      has_suspicious_patterns: true,
      has_password_fields: true,
      external_scripts_count: 5,
      iframe_count: 2,
    },
  },
  {
    id: '2',
    url: 'https://phishing-attempt.com',
    timestamp: new Date().toISOString(),
    status: 'suspicious',
    threatScore: 67,
    classification: 'Phishing',
    method: 'GET',
    indicators: ['phishing_form', 'suspicious_redirect', 'fake_login_page'],
    analysis: {
      ml_prediction: 'Suspicious',
      ml_confidence: 0.82,
      ml_risk_score: 67,
      virustotal_threat_level: 'SUSPICIOUS',
      virustotal_risk_score: 65,
      javascript_risk_score: 70,
    },
    details: {
      has_password_fields: true,
      external_scripts_count: 3,
      iframe_count: 1,
    },
  },
  {
    id: '3',
    url: 'https://safe-website.com',
    timestamp: new Date().toISOString(),
    status: 'safe',
    threatScore: 12,
    classification: 'Benign',
    method: 'GET',
    indicators: [],
    analysis: {
      ml_prediction: 'Benign',
      ml_confidence: 0.99,
      ml_risk_score: 12,
    },
    details: {
      has_obfuscated_js: false,
      has_suspicious_patterns: false,
      has_password_fields: false,
      external_scripts_count: 0,
      iframe_count: 0,
    },
  },
];

// Integration Example Component
export const ExportFunctionalityExample: React.FC = () => {
  const [selectedScan, setSelectedScan] = useState<ScanData | null>(null);

  return (
    <div className="w-full max-w-6xl mx-auto p-6 space-y-6">
      {/* Main Scan Table with Download Dropdown */}
      <div className="space-y-4">
        <h2 className="text-2xl font-bold">Scan Results with Export Options</h2>
        <p className="text-muted-foreground">
          Click "Details" to view full scan information or "Download" to export the scan as PDF or Excel.
        </p>
        <ScanTable 
          scans={exampleScans as any} 
          onViewDetails={(scan) => setSelectedScan(scan as ScanData)}
        />
      </div>

      {/* Scan Details Modal */}
      {selectedScan && (
        <URLScanCard 
          scan={selectedScan}
          isOpen={!!selectedScan}
          onClose={() => setSelectedScan(null)}
        />
      )}

      {/* Feature Information */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="border rounded-lg p-4 bg-blue-50">
          <h3 className="font-bold text-blue-900 mb-2">📄 PDF Export Features</h3>
          <ul className="text-sm text-blue-800 space-y-1">
            <li>✓ Professional formatted report</li>
            <li>✓ Color-coded threat levels</li>
            <li>✓ Complete analysis summary</li>
            <li>✓ Threat details and indicators</li>
            <li>✓ Timestamp and scan ID</li>
          </ul>
        </div>

        <div className="border rounded-lg p-4 bg-green-50">
          <h3 className="font-bold text-green-900 mb-2">📊 Excel Export Features</h3>
          <ul className="text-sm text-green-800 space-y-1">
            <li>✓ Multiple worksheets</li>
            <li>✓ Summary sheet with all metrics</li>
            <li>✓ Detailed threat analysis</li>
            <li>✓ List of detected threats</li>
            <li>✓ Easy data analysis and pivot tables</li>
          </ul>
        </div>
      </div>

      {/* Usage Instructions */}
      <div className="border rounded-lg p-4 bg-yellow-50">
        <h3 className="font-bold text-yellow-900 mb-2">🚀 How to Use</h3>
        <ol className="text-sm text-yellow-800 space-y-2 list-decimal list-inside">
          <li>
            <strong>View Scan Results:</strong> Each row in the table displays a scan result with URL, status, and threat score.
          </li>
          <li>
            <strong>Download Report:</strong> Click the "Download ▼" button in the Actions column.
          </li>
          <li>
            <strong>Choose Format:</strong> Select "Download as PDF" or "Download as Excel" from the dropdown.
          </li>
          <li>
            <strong>Wait for Generation:</strong> The button shows "Generating..." while the report is being created.
          </li>
          <li>
            <strong>Success Notification:</strong> A toast message confirms successful download.
          </li>
          <li>
            <strong>View Details:</strong> Click "Details" button to see full scan analysis in a modal.
          </li>
        </ol>
      </div>

      {/* Accessibility Features */}
      <div className="border rounded-lg p-4 bg-purple-50">
        <h3 className="font-bold text-purple-900 mb-2">♿ Accessibility Features</h3>
        <ul className="text-sm text-purple-800 space-y-1">
          <li>✓ Keyboard navigation (Tab, Enter, Arrow keys)</li>
          <li>✓ Escape key to close dropdown</li>
          <li>✓ ARIA labels and roles for screen readers</li>
          <li>✓ Focus visible states for keyboard users</li>
          <li>✓ Semantic HTML structure</li>
        </ul>
      </div>

      {/* Technical Details */}
      <div className="border rounded-lg p-4 bg-gray-50">
        <h3 className="font-bold text-gray-900 mb-2">⚙️ Technical Implementation</h3>
        <div className="text-sm text-gray-800 space-y-2">
          <p>
            <strong>Components Used:</strong>
          </p>
          <ul className="list-disc list-inside space-y-1">
            <li>DownloadDropdown.tsx - Main dropdown component with state management</li>
            <li>reportGenerator.ts - Service for PDF and Excel generation</li>
            <li>ScanTable.tsx - Updated to include download button</li>
          </ul>
          <p className="mt-4">
            <strong>Libraries:</strong> jsPDF (PDF), XLSX (Excel), Sonner (Toast notifications)
          </p>
        </div>
      </div>
    </div>
  );
};

export default ExportFunctionalityExample;
