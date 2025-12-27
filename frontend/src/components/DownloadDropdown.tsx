import React, { useState, useRef, useEffect } from 'react';
import { ChevronDown } from 'lucide-react';
import { reportGenerator } from '@/services/reportGenerator';
import { toast } from 'sonner';

interface DownloadDropdownProps {
  scan: any;
}

const DownloadDropdown: React.FC<DownloadDropdownProps> = ({ scan }) => {
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    console.log('✅ DownloadDropdown rendered for scan:', scan?.id || scan?.url);
  }, [scan?.id || scan?.url]);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsDropdownOpen(false);
      }
    };

    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, []);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsDropdownOpen(false);
      }
    };

    if (isDropdownOpen) {
      document.addEventListener('keydown', handleKeyDown);
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [isDropdownOpen]);

  const toggleDropdown = () => {
    if (!isGenerating) {
      setIsDropdownOpen(!isDropdownOpen);
    }
  };

  // Transform scan data to match ScanData interface
  const prepareScanData = () => {
    return {
      id: scan.id || scan.url || 'scan-' + Date.now(),
      url: scan.url || '',
      timestamp: scan.timestamp || new Date().toISOString(),
      status: scan.final_classification || scan.classification || scan.status || 'unknown',
      threatScore: scan.overall_risk || scan.risk_score || 0,
      classification: scan.final_classification || scan.classification || 'Unknown',
      method: scan.method || 'GET',
      indicators: scan.threat_indicators || scan.indicators || [],
      analysis: {
        ml_prediction: scan.ml_prediction || undefined,
        ml_confidence: scan.ml_confidence || undefined,
        ml_risk_score: scan.ml_risk_score || scan.overall_risk || 0,
        virustotal_threat_level: scan.virustotal_threat_level || undefined,
        virustotal_risk_score: scan.virustotal_risk_score || undefined,
        javascript_risk_score: scan.javascript_risk_score || undefined,
        pattern_risk_score: scan.pattern_risk_score || undefined,
        page_risk_score: scan.page_risk_score || undefined,
      },
      details: {
        has_obfuscated_js: scan.has_obfuscated_js || false,
        has_suspicious_patterns: scan.has_suspicious_patterns || false,
        has_password_fields: scan.has_password_fields || false,
        external_scripts_count: scan.external_scripts_count || 0,
        iframe_count: scan.iframe_count || 0,
      },
    };
  };

  const handleExport = async (format: 'pdf' | 'excel') => {
    setIsDropdownOpen(false);
    setIsGenerating(true);

    try {
      const scanData = prepareScanData();
      console.log('📊 Generating report for scan:', scanData);

      if (format === 'pdf') {
        await reportGenerator.generatePDFReport(scanData);
        toast.success('✅ PDF report downloaded successfully!', {
          duration: 3000,
        });
      } else if (format === 'excel') {
        await reportGenerator.generateExcelReport(scanData);
        toast.success('✅ Excel report downloaded successfully!', {
          duration: 3000,
        });
      }
    } catch (error) {
      console.error('❌ Export error:', error);
      toast.error('❌ Failed to generate report. Please try again.', {
        duration: 3000,
      });
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="relative inline-block" ref={dropdownRef}>
      <button
        className="inline-flex items-center justify-center gap-1 px-3 py-2 rounded-md border border-blue-400 bg-blue-100 text-blue-800 hover:bg-blue-200 transition-colors"
        onClick={toggleDropdown}
        disabled={isGenerating}
        title="Download report as PDF or Excel"
      >
        {isGenerating ? (
          <svg className="w-5 h-5 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
        ) : (
          <>
            <svg className="w-5 h-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            <ChevronDown className={`w-4 h-4 transition-transform ${isDropdownOpen ? 'rotate-180' : ''}`} />
          </>
        )}
      </button>

      {isDropdownOpen && !isGenerating && (
        <div className="absolute right-0 mt-2 w-56 bg-white border-2 border-blue-400 rounded-lg shadow-xl z-50">
          <button
            className="w-full text-left px-4 py-3 text-sm text-gray-800 hover:bg-blue-50 flex items-center gap-3 font-semibold first:rounded-t-md border-b border-gray-200 transition-colors"
            onClick={() => handleExport('pdf')}
            title="Download as PDF file"
          >
            <span>📄</span>
            <span>Download as PDF</span>
          </button>
          <button
            className="w-full text-left px-4 py-3 text-sm text-gray-800 hover:bg-blue-50 flex items-center gap-3 font-semibold last:rounded-b-md transition-colors"
            onClick={() => handleExport('excel')}
            title="Download as Excel file"
          >
            <span>📊</span>
            <span>Download as Excel</span>
          </button>
        </div>
      )}
    </div>
  );
};

export default DownloadDropdown;
