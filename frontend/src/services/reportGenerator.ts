// Report Generator Service - PDF and Excel exports with report cleaning
import jsPDF from 'jspdf';
import * as XLSX from 'xlsx';

export interface ScanData {
  id: string | number;
  url: string;
  timestamp: string;
  status: string;
  threatScore: number;
  classification?: string;
  method?: string;
  indicators?: string[];
  analysis?: {
    ml_prediction?: string;
    ml_confidence?: number;
    ml_risk_score?: number;
    virustotal_threat_level?: string;
    virustotal_risk_score?: number;
    javascript_risk_score?: number;
    pattern_risk_score?: number;
    page_risk_score?: number;
  };
  details?: {
    has_obfuscated_js?: boolean;
    has_suspicious_patterns?: boolean;
    has_password_fields?: boolean;
    external_scripts_count?: number;
    iframe_count?: number;
  };
}

class ReportGenerator {
  private getThreatLevel = (score: number): string => {
    if (score >= 70) return 'CRITICAL';
    if (score >= 40) return 'SUSPICIOUS';
    return 'SAFE';
  };

  private getThreatColor = (score: number): [number, number, number] => {
    if (score >= 70) return [220, 38, 38]; // red-600 for CRITICAL
    if (score >= 40) return [241, 196, 15]; // yellow-600 for SUSPICIOUS
    return [34, 197, 94]; // green-600 for SAFE
  };

  private async callReportCleaningAPI(scan: ScanData): Promise<{ success: boolean; cleaned_report?: string; threat_data?: any }> {
    try {
      const rawReport = `
SCAN REPORT - ${scan.id}
Timestamp: ${this.formatDate(scan.timestamp)}
URL: ${scan.url}
Classification: ${scan.classification || 'Unknown'}
Threat Level: ${this.getThreatLevel(scan.threatScore)}
Risk Score: ${scan.threatScore}%

DETAILS:
${scan.details ? Object.entries(scan.details).map(([key, value]) => `${key}: ${value}`).join('\n') : 'No details available'}

ANALYSIS:
${scan.analysis ? Object.entries(scan.analysis).map(([key, value]) => `${key}: ${value}`).join('\n') : 'No analysis available'}

INDICATORS:
${scan.indicators?.join('\n') || 'No indicators detected'}
      `.trim();

      const response = await fetch('/api/reports/clean', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          raw_report: rawReport,
          use_llm: false,
          scan_id: scan.id,
        }),
      });

      if (!response.ok) {
        console.warn('Report cleaning API call failed');
        return { success: false };
      }

      const result = await response.json();
      return result;
    } catch (error) {
      console.warn('Error calling report cleaning API:', error);
      return { success: false };
    }
  }

  async generatePDFReport(scan: ScanData): Promise<void> {
    try {
      // Call report cleaning API
      const cleanedData = await this.callReportCleaningAPI(scan);
      
      const pdf = new jsPDF();
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      let yPosition = 20;

      const threatLevel = this.getThreatLevel(scan.threatScore);
      const threatColor = this.getThreatColor(scan.threatScore);

      // ===== HEADER =====
      pdf.setFillColor(44, 62, 80);
      pdf.rect(0, 0, pageWidth, 35, 'F');
      pdf.setTextColor(255, 255, 255);
      pdf.setFontSize(22);
      pdf.setFont(undefined, 'bold');
      pdf.text('SECURITY SCAN REPORT', 20, 20);

      pdf.setFontSize(12);
      pdf.setTextColor(...threatColor);
      pdf.text(threatLevel, pageWidth - 50, 20);

      pdf.setTextColor(0, 0, 0);
      yPosition = 50;

      // Use cleaned report if available
      if (cleanedData.success && cleanedData.cleaned_report) {
        // Render cleaned markdown
        this.renderMarkdownLines(pdf, cleanedData.cleaned_report, pageWidth, pageHeight, yPosition);
      } else {
        // Fallback to manual rendering
        this.renderScanData(pdf, scan, pageWidth, pageHeight, yPosition, threatColor);
      }

      // ===== FOOTER =====
      pdf.setFont(undefined, 'normal');
      pdf.setFontSize(8);
      pdf.setTextColor(128, 128, 128);
      pdf.text(`Report generated on ${new Date().toLocaleString()}`, 20, pageHeight - 10);

      const filename = `scan-report-${scan.id}-${this.getTimestampForFilename()}.pdf`;
      pdf.save(filename);
      console.log('PDF generated:', filename);
    } catch (error) {
      console.error('PDF generation error:', error);
      throw new Error('Failed to generate PDF');
    }
  }

  private renderMarkdownLines(pdf: any, markdown: string, pageWidth: number, pageHeight: number, startY: number): void {
    let yPosition = startY;
    const lines = markdown.split('\n');

    lines.forEach((line) => {
      if (!line.trim()) {
        yPosition += 4;
        return;
      }

      if (yPosition > pageHeight - 20) {
        pdf.addPage();
        yPosition = 20;
      }

      // Parse and render line
      if (line.startsWith('# ')) {
        pdf.setFontSize(16);
        pdf.setFont(undefined, 'bold');
        pdf.setTextColor(44, 62, 80);
        const text = line.substring(2);
        const wrapped = pdf.splitTextToSize(text, pageWidth - 40);
        pdf.text(wrapped, 20, yPosition);
        yPosition += wrapped.length * 7 + 4;
      } else if (line.startsWith('## ')) {
        pdf.setFontSize(13);
        pdf.setFont(undefined, 'bold');
        pdf.setTextColor(44, 62, 80);
        pdf.text(line.substring(3), 20, yPosition);
        yPosition += 7;
      } else if (line.startsWith('### ')) {
        pdf.setFontSize(11);
        pdf.setFont(undefined, 'bold');
        pdf.setTextColor(60, 80, 100);
        pdf.text(line.substring(4), 20, yPosition);
        yPosition += 6;
      } else if (line.startsWith('- ')) {
        pdf.setFontSize(10);
        pdf.setFont(undefined, 'normal');
        pdf.setTextColor(0, 0, 0);
        const text = line.substring(2);
        const wrapped = pdf.splitTextToSize(text, pageWidth - 50);
        pdf.text('\u2022', 20, yPosition);
        pdf.text(wrapped, 25, yPosition);
        yPosition += wrapped.length * 5 + 3;
      } else if (line.includes(':') && (line.startsWith('**') || line.includes('**'))) {
        pdf.setFontSize(10);
        pdf.setFont(undefined, 'bold');
        pdf.setTextColor(0, 0, 0);
        const cleanLine = line.replace(/\*\*/g, '');
        const [key, ...valueParts] = cleanLine.split(':');
        pdf.text(key + ':', 20, yPosition);
        pdf.setFont(undefined, 'normal');
        const value = valueParts.join(':').trim();
        const wrapped = pdf.splitTextToSize(value, pageWidth - 60);
        pdf.text(wrapped, 80, yPosition);
        yPosition += Math.max(wrapped.length * 5, 5) + 2;
      } else {
        pdf.setFontSize(10);
        pdf.setFont(undefined, 'normal');
        pdf.setTextColor(0, 0, 0);
        const wrapped = pdf.splitTextToSize(line, pageWidth - 40);
        pdf.text(wrapped, 20, yPosition);
        yPosition += wrapped.length * 5 + 2;
      }
    });
  }

  private renderScanData(pdf: any, scan: ScanData, pageWidth: number, pageHeight: number, yPosition: number, threatColor: [number, number, number]): void {
    const threatLevel = this.getThreatLevel(scan.threatScore);

    // Executive Summary
    pdf.setFontSize(12);
    pdf.setFont(undefined, 'bold');
    pdf.setTextColor(44, 62, 80);
    pdf.text('EXECUTIVE SUMMARY', 20, yPosition);
    yPosition += 8;

    pdf.setFontSize(10);
    pdf.setFont(undefined, 'bold');
    pdf.setTextColor(0, 0, 0);
    const summaryData = [
      ['Threat Level:', threatLevel],
      ['Risk Score:', `${scan.threatScore.toFixed(1)}%`],
      ['Scan Date:', this.formatDate(scan.timestamp)],
      ['URL:', scan.url.substring(0, 60)],
    ];

    summaryData.forEach(([label, value]) => {
      if (yPosition > pageHeight - 25) {
        pdf.addPage();
        yPosition = 20;
      }
      pdf.setFont(undefined, 'bold');
      pdf.text(label, 20, yPosition);
      pdf.setFont(undefined, 'normal');
      const wrapped = pdf.splitTextToSize(String(value), pageWidth - 80);
      pdf.text(wrapped, 80, yPosition);
      yPosition += 6;
    });

    yPosition += 8;

    // Threat Indicators
    if (yPosition > pageHeight - 50) {
      pdf.addPage();
      yPosition = 20;
    }

    pdf.setFontSize(12);
    pdf.setFont(undefined, 'bold');
    pdf.setTextColor(44, 62, 80);
    pdf.text('THREAT INDICATORS', 20, yPosition);
    yPosition += 8;

    pdf.setFontSize(10);
    const indicators = [
      ['Obfuscated JS:', scan.details?.has_obfuscated_js ? 'DETECTED' : 'CLEAR'],
      ['Suspicious Patterns:', scan.details?.has_suspicious_patterns ? 'DETECTED' : 'CLEAR'],
      ['Password Fields:', scan.details?.has_password_fields ? 'PRESENT' : 'ABSENT'],
      [`External Scripts: ${scan.details?.external_scripts_count || 0}`, ''],
      [`Embedded iFrames: ${scan.details?.iframe_count || 0}`, ''],
    ];

    indicators.forEach(([indicator, status]) => {
      if (yPosition > pageHeight - 25) {
        pdf.addPage();
        yPosition = 20;
      }
      pdf.setFont(undefined, 'normal');
      pdf.setTextColor(0, 0, 0);
      pdf.text(indicator, 20, yPosition);
      if (status) {
        pdf.text(status, pageWidth - 60, yPosition);
      }
      yPosition += 6;
    });

    yPosition += 8;

    // Recommendations
    if (yPosition > pageHeight - 50) {
      pdf.addPage();
      yPosition = 20;
    }

    pdf.setFontSize(12);
    pdf.setFont(undefined, 'bold');
    pdf.setTextColor(44, 62, 80);
    pdf.text('RECOMMENDATIONS', 20, yPosition);
    yPosition += 8;

    const recommendations = this.getRecommendations(scan.threatScore);
    Object.entries(recommendations).forEach(([category, items]: [string, string[]]) => {
      if (yPosition > pageHeight - 40) {
        pdf.addPage();
        yPosition = 20;
      }

      pdf.setFontSize(10);
      pdf.setFont(undefined, 'bold');
      pdf.setTextColor(44, 62, 80);
      pdf.text(category, 20, yPosition);
      yPosition += 6;

      pdf.setFont(undefined, 'normal');
      pdf.setFontSize(9);
      pdf.setTextColor(0, 0, 0);

      items.forEach((item: string) => {
        if (yPosition > pageHeight - 20) {
          pdf.addPage();
          yPosition = 20;
        }
        const wrapped = pdf.splitTextToSize(`• ${item}`, pageWidth - 50);
        pdf.text(wrapped, 25, yPosition);
        yPosition += wrapped.length * 4 + 2;
      });

      yPosition += 4;
    });
  }

  async generateExcelReport(scan: ScanData): Promise<void> {
    try {
      const cleanedData = await this.callReportCleaningAPI(scan);
      
      const workbook = XLSX.utils.book_new();
      const threatLevel = this.getThreatLevel(scan.threatScore);

      // Summary Sheet
      const summaryData = [
        ['Security Scan Report'],
        [],
        ['EXECUTIVE SUMMARY'],
        ['Threat Level', threatLevel],
        ['Risk Score (%)', scan.threatScore],
        ['Scan Date', this.formatDate(scan.timestamp)],
        [],
        ['SCAN INFORMATION'],
        ['Scan ID', scan.id],
        ['URL', scan.url],
        ['Classification', scan.classification || 'N/A'],
        ['Method', scan.method || 'GET'],
      ];

      if (scan.analysis) {
        summaryData.push([]);
        summaryData.push(['ANALYSIS RESULTS']);
        if (scan.analysis.ml_prediction) summaryData.push(['ML Prediction', scan.analysis.ml_prediction]);
        if (scan.analysis.ml_confidence) summaryData.push(['ML Confidence (%)', (scan.analysis.ml_confidence * 100).toFixed(1)]);
        if (scan.analysis.ml_risk_score) summaryData.push(['ML Risk Score (%)', scan.analysis.ml_risk_score]);
        if (scan.analysis.virustotal_threat_level) summaryData.push(['VirusTotal Level', scan.analysis.virustotal_threat_level]);
      }

      const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
      summarySheet['!cols'] = [{ wch: 30 }, { wch: 50 }];
      XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');

      // Details Sheet
      if (scan.details) {
        const detailsData = [
          ['Threat Details'],
          [],
          ['Aspect', 'Value', 'Interpretation'],
          ['Obfuscated JavaScript', scan.details.has_obfuscated_js ? 'Yes' : 'No', 'Code obfuscation detected'],
          ['Suspicious Patterns', scan.details.has_suspicious_patterns ? 'Yes' : 'No', 'Suspicious patterns found'],
          ['Password Fields', scan.details.has_password_fields ? 'Yes' : 'No', 'Password fields in form'],
          ['External Scripts', scan.details.external_scripts_count || 0, 'Number of external scripts'],
          ['iFrames', scan.details.iframe_count || 0, 'Number of embedded iframes'],
        ];

        const detailsSheet = XLSX.utils.aoa_to_sheet(detailsData);
        detailsSheet['!cols'] = [{ wch: 25 }, { wch: 20 }, { wch: 35 }];
        XLSX.utils.book_append_sheet(workbook, detailsSheet, 'Details');
      }

      // Threats Sheet
      if (scan.indicators && scan.indicators.length > 0) {
        const indicatorsData = [
          ['Detected Threats'],
          [],
          ['Threat Indicator'],
          ...scan.indicators.map((indicator) => [indicator]),
        ];

        const indicatorsSheet = XLSX.utils.aoa_to_sheet(indicatorsData);
        indicatorsSheet['!cols'] = [{ wch: 60 }];
        XLSX.utils.book_append_sheet(workbook, indicatorsSheet, 'Threats');
      }

      // Recommendations Sheet
      const recommendations = this.getRecommendations(scan.threatScore);
      const recommendationsData = [['Recommendations'], []];

      Object.entries(recommendations).forEach(([category, items]) => {
        recommendationsData.push([category]);
        items.forEach((item) => {
          recommendationsData.push([`  • ${item}`]);
        });
        recommendationsData.push([]);
      });

      const recommendationsSheet = XLSX.utils.aoa_to_sheet(recommendationsData);
      recommendationsSheet['!cols'] = [{ wch: 80 }];
      XLSX.utils.book_append_sheet(workbook, recommendationsSheet, 'Recommendations');

      const filename = `scan-report-${scan.id}-${this.getTimestampForFilename()}.xlsx`;
      XLSX.writeFile(workbook, filename);
      console.log('Excel generated:', filename);
    } catch (error) {
      console.error('Excel generation error:', error);
      throw new Error('Failed to generate Excel');
    }
  }

  private getRecommendations(score: number): Record<string, string[]> {
    if (score >= 70) {
      return {
        'IMMEDIATE ACTIONS (1-24 hours)': [
          'Block the URL from all network access immediately',
          'Alert security team and management',
          'Isolate any affected systems',
          'Document the incident with timestamp',
        ],
        'SHORT-TERM MITIGATIONS (1-7 days)': [
          'Conduct full malware scan on affected endpoints',
          'Review firewall logs for suspicious connections',
          'Update antivirus and threat detection signatures',
          'Brief users on the threat and prevention measures',
        ],
        'LONG-TERM STRATEGY (1-3 months)': [
          'Implement advanced threat protection system',
          'Deploy behavioral analysis tools',
          'Establish incident response procedures',
          'Schedule security awareness training',
        ],
      };
    } else if (score >= 40) {
      return {
        'IMMEDIATE ACTIONS (1-24 hours)': [
          'Add URL to watchlist for further monitoring',
          'Review the content for suspicious characteristics',
          'Brief security team on findings',
        ],
        'SHORT-TERM MITIGATIONS (1-7 days)': [
          'Enhance browser security filters',
          'Run targeted malware scans on recent history',
          'Update security policies if needed',
          'Train users on phishing and suspicious links',
        ],
        'LONG-TERM STRATEGY (1-3 months)': [
          'Implement SSL/TLS pinning for sensitive connections',
          'Deploy advanced email security solutions',
          'Enhance endpoint detection and response (EDR)',
          'Conduct quarterly security assessments',
        ],
      };
    } else {
      return {
        'IMMEDIATE ACTIONS (1-24 hours)': [
          'Log the scan result for compliance records',
          'No immediate action required',
        ],
        'SHORT-TERM MITIGATIONS (1-7 days)': [
          'Monitor for any changes in site behavior',
          'Keep security tools updated',
        ],
        'LONG-TERM STRATEGY (1-3 months)': [
          'Maintain regular security assessments',
          'Continue monitoring for emerging threats',
          'Review and update security policies periodically',
        ],
      };
    }
  }

  private formatDate = (timestamp: string | number): string => {
    try {
      const date = typeof timestamp === 'number' ? new Date(timestamp) : new Date(timestamp);
      return date.toLocaleString();
    } catch {
      return 'Unknown';
    }
  };

  private getTimestampForFilename = (): string => {
    const now = new Date();
    return now.toISOString().replace(/[:.]/g, '-').split('T')[0];
  };

  generateHTMLReport = (scan: ScanData): string => {
    const threatLevel = this.getThreatLevel(scan.threatScore);
    const riskPosition = Math.min(scan.threatScore, 100);
    const threatColorMap = {
      critical: '#E74C3C',
      suspicious: '#F1C40F',
      safe: '#27AE60'
    };
    const threatColor = threatColorMap[threatLevel.toLowerCase() as keyof typeof threatColorMap];

    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; line-height: 1.6; color: #333; }
        .report { max-width: 1200px; margin: 0 auto; padding: 20px; background: #fff; }
        .header { background: #2C3E50; color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 28px; }
        .badge { display: inline-block; padding: 10px 20px; border-radius: 5px; font-weight: bold; font-size: 18px; background-color: ${threatColor}; color: ${threatLevel === 'SUSPICIOUS' ? '#000' : '#fff'}; }
        section { margin-bottom: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px; }
        section h2 { color: #2C3E50; font-size: 22px; margin-bottom: 20px; border-bottom: 3px solid #2C3E50; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; background: white; margin: 15px 0; }
        table thead { background: #2C3E50; color: white; }
        table th, table td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        table tbody tr:nth-child(even) { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="report">
        <header class="header">
            <h1>SECURITY SCAN REPORT</h1>
            <div class="badge">${threatLevel}</div>
        </header>

        <section>
            <h2>EXECUTIVE SUMMARY</h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Threat Level</td><td>${threatLevel}</td></tr>
                <tr><td>Risk Score</td><td>${scan.threatScore.toFixed(1)}%</td></tr>
                <tr><td>Scan Date</td><td>${this.formatDate(scan.timestamp)}</td></tr>
                <tr><td>URL</td><td>${scan.url}</td></tr>
            </table>
        </section>

        <section>
            <h2>THREAT INDICATORS</h2>
            <table>
                <tr><th>Indicator</th><th>Status</th></tr>
                <tr><td>Obfuscated JS</td><td>${scan.details?.has_obfuscated_js ? 'DETECTED' : 'CLEAR'}</td></tr>
                <tr><td>Suspicious Patterns</td><td>${scan.details?.has_suspicious_patterns ? 'DETECTED' : 'CLEAR'}</td></tr>
                <tr><td>Password Fields</td><td>${scan.details?.has_password_fields ? 'PRESENT' : 'ABSENT'}</td></tr>
                <tr><td>External Scripts</td><td>${scan.details?.external_scripts_count || 0}</td></tr>
                <tr><td>Embedded iFrames</td><td>${scan.details?.iframe_count || 0}</td></tr>
            </table>
        </section>

        <footer style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; font-size: 12px;">
            <p>Report generated on ${new Date().toLocaleString()}</p>
        </footer>
    </div>
</body>
</html>
    `;
  };
}

export const reportGenerator = new ReportGenerator();
