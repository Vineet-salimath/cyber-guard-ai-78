// Report Generator Service - PDF and Excel exports with enhanced professional reports

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

  async generatePDFReport(scan: ScanData): Promise<void> {
    try {
      const pdf = new jsPDF();
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      let yPosition = 20;

      // Color scheme
      const headerColor = [44, 62, 80]; // #2C3E50
      const threatColor = this.getThreatColor(scan.threatScore);

      // ===== HEADER =====
      pdf.setFillColor(headerColor[0], headerColor[1], headerColor[2]);
      pdf.rect(0, 0, pageWidth, 35, 'F');

      pdf.setTextColor(255, 255, 255);
      pdf.setFontSize(22);
      pdf.setFont(undefined, 'bold');
      pdf.text('🛡️  SECURITY SCAN REPORT', 20, 20);

      // Threat Badge
      const threatLevel = this.getThreatLevel(scan.threatScore);
      pdf.setFontSize(12);
      pdf.setFont(undefined, 'bold');
      pdf.setTextColor(...threatColor);
      pdf.text(threatLevel, pageWidth - 50, 20);

      // Reset for content
      pdf.setTextColor(0, 0, 0);
      yPosition = 50;

      // ===== EXECUTIVE SUMMARY =====
      this.addSectionHeader(pdf, '📊 EXECUTIVE SUMMARY', 20, yPosition);
      yPosition += 10;

      // Summary Items
      pdf.setFontSize(10);
      pdf.setFont(undefined, 'bold');
      pdf.text('Threat Level:', 25, yPosition);
      pdf.setFont(undefined, 'normal');
      pdf.setTextColor(...threatColor);
      pdf.text(threatLevel, 65, yPosition);
      pdf.setTextColor(0, 0, 0);
      yPosition += 7;

      pdf.setFont(undefined, 'bold');
      pdf.text('Risk Score:', 25, yPosition);
      pdf.setFont(undefined, 'normal');
      pdf.text(`${scan.threatScore.toFixed(1)}%`, 65, yPosition);
      yPosition += 7;

      pdf.setFont(undefined, 'bold');
      pdf.text('Scan Date:', 25, yPosition);
      pdf.setFont(undefined, 'normal');
      pdf.text(this.formatDate(scan.timestamp), 65, yPosition);
      yPosition += 12;

      // Risk Meter Visualization
      this.drawRiskMeter(pdf, scan.threatScore, 25, yPosition, pageWidth - 50);
      yPosition += 15;

      // ===== THREAT DETAILS TABLE =====
      if (yPosition > pageHeight - 80) {
        pdf.addPage();
        yPosition = 20;
      }

      this.addSectionHeader(pdf, '🔍 THREAT DETAILS', 20, yPosition);
      yPosition += 10;

      const threatDetailsData = [
        ['Scan ID', String(scan.id).substring(0, 50), 'Unique identifier'],
        ['Threat Level', threatLevel, 'Indicates potential risk'],
        ['Risk Score', `${scan.threatScore.toFixed(1)}%`, 'ML-based likelihood'],
        ['URL', scan.url.substring(0, 50), 'Target of scan'],
        ['Classification', scan.classification || 'Unknown', 'Threat type'],
      ];

      yPosition = this.drawDetailTable(pdf, threatDetailsData, 20, yPosition, pageWidth - 40);
      yPosition += 8;

      // ===== THREAT INDICATORS TABLE =====
      if (yPosition > pageHeight - 100) {
        pdf.addPage();
        yPosition = 20;
      }

      this.addSectionHeader(pdf, '⚠️ THREAT INDICATORS', 20, yPosition);
      yPosition += 10;

      const indicatorRows = this.getIndicatorRows(scan);
      yPosition = this.drawIndicatorTable(pdf, indicatorRows, 20, yPosition, pageWidth - 40);
      yPosition += 8;

      // ===== ANALYSIS RESULTS =====
      if (yPosition > pageHeight - 100) {
        pdf.addPage();
        yPosition = 20;
      }

      if (scan.analysis) {
        this.addSectionHeader(pdf, '🔬 ANALYSIS RESULTS', 20, yPosition);
        yPosition += 10;

        pdf.setFontSize(10);
        const analysisItems = [
          ['ML Prediction', scan.analysis.ml_prediction || 'N/A'],
          ['ML Confidence', scan.analysis.ml_confidence ? `${(scan.analysis.ml_confidence * 100).toFixed(1)}%` : 'N/A'],
          ['ML Risk Score', scan.analysis.ml_risk_score ? `${scan.analysis.ml_risk_score.toFixed(1)}%` : 'N/A'],
          ['VirusTotal Level', scan.analysis.virustotal_threat_level || 'N/A'],
        ];

        analysisItems.forEach((item) => {
          if (yPosition > pageHeight - 25) {
            pdf.addPage();
            yPosition = 20;
          }
          pdf.setFont(undefined, 'bold');
          pdf.text(`${item[0]}:`, 25, yPosition);
          pdf.setFont(undefined, 'normal');
          pdf.text(String(item[1]), 95, yPosition);
          yPosition += 6;
        });

        yPosition += 5;
      }

      // ===== RECOMMENDATIONS =====
      if (yPosition > pageHeight - 100) {
        pdf.addPage();
        yPosition = 20;
      }

      this.addSectionHeader(pdf, '💡 RECOMMENDATIONS', 20, yPosition);
      yPosition += 10;

      const recommendations = this.getRecommendations(scan.threatScore);
      Object.entries(recommendations).forEach(([category, items]: [string, string[]]) => {
        if (yPosition > pageHeight - 40) {
          pdf.addPage();
          yPosition = 20;
        }

        pdf.setFontSize(10);
        pdf.setFont(undefined, 'bold');
        pdf.text(category, 25, yPosition);
        yPosition += 6;

        pdf.setFont(undefined, 'normal');
        pdf.setFontSize(9);
        items.forEach((item: string) => {
          if (yPosition > pageHeight - 20) {
            pdf.addPage();
            yPosition = 20;
          }
          const wrappedText = pdf.splitTextToSize(`• ${item}`, pageWidth - 60);
          pdf.text(wrappedText, 30, yPosition);
          yPosition += wrappedText.length * 4 + 2;
        });

        yPosition += 5;
      });

      // ===== FOOTER =====
      pdf.setFont(undefined, 'normal');
      pdf.setFontSize(8);
      pdf.setTextColor(128, 128, 128);
      const timestamp = new Date().toLocaleString();
      pdf.text(`Report generated on ${timestamp}`, 20, pageHeight - 10);

      // Save PDF
      const filename = `malware-sniffer-report-${scan.id}-${this.getTimestampForFilename()}.pdf`;
      pdf.save(filename);

      console.log('✅ PDF report generated successfully:', filename);
    } catch (error) {
      console.error('❌ Error generating PDF report:', error);
      throw new Error('Failed to generate PDF report');
    }
  }

  private addSectionHeader(pdf: any, title: string, x: number, y: number): void {
    pdf.setFontSize(12);
    pdf.setFont(undefined, 'bold');
    pdf.setTextColor(44, 62, 80);
    pdf.text(title, x, y);
    pdf.setDrawColor(44, 62, 80);
    pdf.line(x, y + 2, x + 50, y + 2);
  }

  private drawRiskMeter(pdf: any, score: number, x: number, y: number, width: number): void {
    const colors = [
      [39, 174, 96],
      [241, 196, 15],
      [220, 38, 38],
    ];

    const segmentWidth = width / 3;
    colors.forEach((color, index) => {
      pdf.setFillColor(...color);
      pdf.rect(x + index * segmentWidth, y, segmentWidth, 8, 'F');
    });

    const position = (score / 100) * width;
    pdf.setFillColor(44, 62, 80);
    pdf.circle(x + position, y + 4, 3, 'F');

    pdf.setFontSize(9);
    pdf.setFont(undefined, 'normal');
    pdf.text(`Risk Level: ${score.toFixed(1)}%`, x, y + 15);
  }

  private drawDetailTable(pdf: any, data: string[][], x: number, y: number, width: number): number {
    pdf.setFontSize(9);
    const rowHeight = 8;
    const colWidths = [width * 0.25, width * 0.35, width * 0.4];

    data.forEach((row, index) => {
      if (y > pdf.internal.pageSize.getHeight() - 20) {
        pdf.addPage();
        y = 20;
      }

      if (index % 2 === 0) {
        pdf.setFillColor(248, 249, 250);
        pdf.rect(x, y - 6, width, rowHeight, 'F');
      }

      pdf.setTextColor(0, 0, 0);
      pdf.setFont(index === 0 ? 'bold' : 'normal');
      
      let colX = x + 2;
      row.forEach((cell, colIndex) => {
        const wrappedText = pdf.splitTextToSize(String(cell), colWidths[colIndex] - 4);
        pdf.text(wrappedText, colX, y);
        colX += colWidths[colIndex];
      });

      y += rowHeight;
    });

    return y;
  }

  private drawIndicatorTable(pdf: any, data: any[], x: number, y: number, width: number): number {
    pdf.setFontSize(9);
    const rowHeight = 8;
    const colWidths = [width * 0.35, width * 0.25, width * 0.4];

    data.forEach((row, index) => {
      if (y > pdf.internal.pageSize.getHeight() - 20) {
        pdf.addPage();
        y = 20;
      }

      if (index % 2 === 0) {
        pdf.setFillColor(248, 249, 250);
        pdf.rect(x, y - 6, width, rowHeight, 'F');
      }

      pdf.setTextColor(0, 0, 0);
      pdf.setFont(undefined, 'normal');
      
      let colX = x + 2;
      const cellData = [
        `${row.icon} ${row.name}`,
        row.value,
        row.description
      ];
      cellData.forEach((cell, colIndex) => {
        const wrappedText = pdf.splitTextToSize(String(cell), colWidths[colIndex] - 4);
        pdf.text(wrappedText, colX, y);
        colX += colWidths[colIndex];
      });

      y += rowHeight;
    });

    return y;
  }

  private getIndicatorRows(scan: ScanData): any[] {
    return [
      {
        icon: '✗',
        name: 'Obfuscated JS',
        status: scan.details?.has_obfuscated_js ? 'critical' : 'safe',
        value: scan.details?.has_obfuscated_js ? 'DETECTED' : 'CLEAR',
        description: 'Code obfuscation detected in JavaScript'
      },
      {
        icon: '✗',
        name: 'Suspicious Patterns',
        status: scan.details?.has_suspicious_patterns ? 'critical' : 'safe',
        value: scan.details?.has_suspicious_patterns ? 'DETECTED' : 'CLEAR',
        description: 'Suspicious code patterns found'
      },
      {
        icon: '✓',
        name: 'Password Fields',
        status: scan.details?.has_password_fields ? 'warning' : 'safe',
        value: scan.details?.has_password_fields ? 'PRESENT' : 'ABSENT',
        description: 'Password input fields detected in form'
      },
      {
        icon: '📄',
        name: 'External Scripts',
        status: (scan.details?.external_scripts_count || 0) > 5 ? 'warning' : 'safe',
        value: `${scan.details?.external_scripts_count || 0}`,
        description: `Number of external script sources: ${scan.details?.external_scripts_count || 0}`
      },
      {
        icon: '🖼️',
        name: 'Embedded iframes',
        status: (scan.details?.iframe_count || 0) > 3 ? 'warning' : 'safe',
        value: `${scan.details?.iframe_count || 0}`,
        description: `Number of embedded frames: ${scan.details?.iframe_count || 0}`
      },
    ];
  }

  private getRecommendations(score: number): Record<string, string[]> {
    if (score >= 70) {
      return {
        'IMMEDIATE ACTIONS (1-24 hours)': [
          'Block the URL from all network access immediately',
          'Alert security team and management about the threat',
          'Isolate any affected systems from the network',
          'Document the incident with timestamp and details',
        ],
        'SHORT-TERM MITIGATIONS (1-7 days)': [
          'Conduct full malware scan on all affected endpoints',
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

  async generateExcelReport(scan: ScanData): Promise<void> {
    try {
      const workbook = XLSX.utils.book_new();

      // Sheet 1: Executive Summary
      const threatLevel = this.getThreatLevel(scan.threatScore);
      const summaryData = [
        ['MalwareSniffer Security Scan Report'],
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
        [],
        ['ANALYSIS RESULTS'],
      ];

      if (scan.analysis) {
        if (scan.analysis.ml_prediction) {
          summaryData.push(['ML Prediction', scan.analysis.ml_prediction]);
        }
        if (scan.analysis.ml_confidence) {
          summaryData.push(['ML Confidence (%)', (scan.analysis.ml_confidence * 100).toFixed(1)]);
        }
        if (scan.analysis.ml_risk_score) {
          summaryData.push(['ML Risk Score (%)', scan.analysis.ml_risk_score]);
        }
        if (scan.analysis.virustotal_threat_level) {
          summaryData.push(['VirusTotal Threat Level', scan.analysis.virustotal_threat_level]);
        }
      }

      const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
      summarySheet['!cols'] = [{ wch: 30 }, { wch: 50 }];
      XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');

      // Sheet 2: Threat Details
      if (scan.details) {
        const detailsData = [
          ['Threat Details'],
          [],
          ['Aspect', 'Value', 'Interpretation'],
          ['Obfuscated JavaScript', scan.details.has_obfuscated_js ? 'Yes' : 'No', 'Code obfuscation detected'],
          ['Suspicious Patterns', scan.details.has_suspicious_patterns ? 'Yes' : 'No', 'Suspicious code patterns found'],
          ['Password Fields', scan.details.has_password_fields ? 'Yes' : 'No', 'Password fields in form'],
          ['External Scripts Count', scan.details.external_scripts_count || 0, 'Number of external scripts'],
          ['iFrame Count', scan.details.iframe_count || 0, 'Number of iframes embedded'],
        ];

        const detailsSheet = XLSX.utils.aoa_to_sheet(detailsData);
        detailsSheet['!cols'] = [{ wch: 25 }, { wch: 20 }, { wch: 35 }];
        XLSX.utils.book_append_sheet(workbook, detailsSheet, 'Details');
      }

      // Sheet 3: Detected Threats
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

      // Sheet 4: Recommendations
      const recommendations = this.getRecommendations(scan.threatScore);
      const recommendationsData = [['Recommendations'], []];

      Object.entries(recommendations).forEach(([category, items]) => {
        recommendationsData.push([category]);
        items.forEach((item) => {
          recommendationsData.push([`• ${item}`]);
        });
        recommendationsData.push([]);
      });

      const recommendationsSheet = XLSX.utils.aoa_to_sheet(recommendationsData);
      recommendationsSheet['!cols'] = [{ wch: 80 }];
      XLSX.utils.book_append_sheet(workbook, recommendationsSheet, 'Recommendations');

      // Generate filename and save
      const filename = `malware-sniffer-report-${scan.id}-${this.getTimestampForFilename()}.xlsx`;
      XLSX.writeFile(workbook, filename);

      console.log('✅ Excel report generated successfully:', filename);
    } catch (error) {
      console.error('❌ Error generating Excel report:', error);
      throw new Error('Failed to generate Excel report');
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
    const threatClass = threatLevel.toLowerCase();
    const riskPosition = Math.min(scan.threatScore, 100);

    const threatColorMap = {
      critical: '#E74C3C',
      suspicious: '#F1C40F',
      safe: '#27AE60'
    };

    const threatColor = threatColorMap[threatClass as keyof typeof threatColorMap];

    const recommendationsData = this.getRecommendations(scan.threatScore);
    const indicatorRows = this.getIndicatorRows(scan);

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - ${scan.id}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f5f5;
            line-height: 1.6;
            color: #333;
        }

        .security-report {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #fff;
        }

        .report-header {
            background: #2C3E50;
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .report-header h1 {
            margin: 0;
            font-size: 28px;
        }

        .threat-badge {
            display: inline-block;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 18px;
            text-transform: uppercase;
            background-color: ${threatColor};
            color: ${threatClass === 'suspicious' ? '#000' : '#fff'};
        }

        section {
            margin-bottom: 40px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }

        section h2 {
            color: #2C3E50;
            font-size: 22px;
            font-weight: bold;
            margin-bottom: 20px;
            border-bottom: 3px solid #2C3E50;
            padding-bottom: 10px;
        }

        section h3 {
            color: #34495E;
            font-size: 18px;
            font-weight: bold;
            margin-top: 20px;
            margin-bottom: 15px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .summary-item {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .summary-item strong {
            display: block;
            color: #2C3E50;
            margin-bottom: 10px;
            font-size: 14px;
        }

        .risk-meter {
            height: 40px;
            background: linear-gradient(to right, #27AE60 0%, #F1C40F 50%, #E74C3C 100%);
            border-radius: 20px;
            position: relative;
            margin: 20px 0;
            border: 2px solid #ddd;
        }

        .risk-indicator {
            position: absolute;
            top: -5px;
            width: 50px;
            height: 50px;
            background: #2C3E50;
            border-radius: 50%;
            border: 4px solid white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
            left: ${riskPosition}%;
            transform: translateX(-50%);
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
            margin: 15px 0;
        }

        .data-table thead {
            background: #2C3E50;
            color: white;
        }

        .data-table th {
            padding: 15px;
            text-align: left;
            font-weight: bold;
        }

        .data-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }

        .data-table tbody tr:nth-child(even) {
            background: #f8f9fa;
        }

        .data-table tbody tr:hover {
            background: #e9ecef;
        }

        .status-safe { color: #27AE60; font-weight: bold; }
        .status-warning { color: #F1C40F; font-weight: bold; }
        .status-critical { color: #E74C3C; font-weight: bold; }

        .recommendations ul {
            list-style: none;
            padding: 0;
        }

        .recommendations li {
            padding: 10px 15px;
            margin: 10px 0;
            background: white;
            border-left: 4px solid #3498DB;
            border-radius: 4px;
        }

        .recommendations li::before {
            content: "→ ";
            font-weight: bold;
            color: #3498DB;
            margin-right: 8px;
        }

        .export-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            print-margin-bottom: 0;
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }

        .btn-print {
            background: #3498DB;
            color: white;
        }

        .btn-print:hover {
            background: #2980B9;
        }

        @media print {
            .security-report {
                max-width: 100%;
                padding: 0;
            }

            .export-buttons {
                display: none;
            }

            .no-print {
                display: none;
            }

            section {
                page-break-inside: avoid;
            }
        }

        code {
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="security-report">
        <div class="export-buttons no-print">
            <button class="btn btn-print" onclick="window.print()">🖨️ Print Report</button>
        </div>

        <header class="report-header">
            <h1>🛡️ Security Scan Report</h1>
            <div class="threat-badge">${threatLevel}</div>
        </header>

        <section class="executive-summary">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <strong>Threat Level:</strong>
                    <div class="threat-badge">${threatLevel}</div>
                </div>
                <div class="summary-item">
                    <strong>Risk Score:</strong>
                    <div style="font-size: 24px; color: ${threatColor}; font-weight: bold;">${scan.threatScore.toFixed(1)}%</div>
                </div>
                <div class="summary-item">
                    <strong>Scan Date:</strong>
                    <div>${this.formatDate(scan.timestamp)}</div>
                </div>
            </div>

            <div style="margin-top: 20px;">
                <strong style="display: block; margin-bottom: 10px;">Risk Meter:</strong>
                <div class="risk-meter">
                    <div class="risk-indicator"></div>
                </div>
            </div>
        </section>

        <section class="threat-details">
            <h2>🔍 Threat Details</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Attribute</th>
                        <th>Value</th>
                        <th>Interpretation</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Scan ID</strong></td>
                        <td><code>${String(scan.id).substring(0, 50)}</code></td>
                        <td>Unique identifier for traceability</td>
                    </tr>
                    <tr>
                        <td><strong>Threat Level</strong></td>
                        <td><span class="threat-badge">${threatLevel}</span></td>
                        <td>Indicates potential risk requiring validation</td>
                    </tr>
                    <tr>
                        <td><strong>Risk Score</strong></td>
                        <td><strong style="color: ${threatColor};">${scan.threatScore.toFixed(1)}%</strong></td>
                        <td>ML-based likelihood of threat</td>
                    </tr>
                    <tr>
                        <td><strong>URL</strong></td>
                        <td title="${scan.url}">${scan.url.substring(0, 50)}${scan.url.length > 50 ? '...' : ''}</td>
                        <td>Target of security scan</td>
                    </tr>
                    <tr>
                        <td><strong>Classification</strong></td>
                        <td>${scan.classification || 'Unknown'}</td>
                        <td>Type of detected threat</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section class="threat-detections">
            <h2>⚠️ Threat Indicators</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Indicator</th>
                        <th>Status</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    ${indicatorRows.map(row => `
                    <tr>
                        <td><strong>${row.icon} ${row.name}</strong></td>
                        <td><span class="status-${row.status}">${row.value}</span></td>
                        <td>${row.description}</td>
                    </tr>
                    `).join('')}
                </tbody>
            </table>
        </section>

        ${scan.analysis ? `
        <section class="analysis-results">
            <h2>🔬 Analysis Results</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                    ${scan.analysis.ml_prediction ? `<tr><td><strong>ML Prediction</strong></td><td>${scan.analysis.ml_prediction}</td></tr>` : ''}
                    ${scan.analysis.ml_confidence ? `<tr><td><strong>ML Confidence</strong></td><td>${(scan.analysis.ml_confidence * 100).toFixed(1)}%</td></tr>` : ''}
                    ${scan.analysis.ml_risk_score ? `<tr><td><strong>ML Risk Score</strong></td><td>${scan.analysis.ml_risk_score.toFixed(1)}%</td></tr>` : ''}
                    ${scan.analysis.virustotal_threat_level ? `<tr><td><strong>VirusTotal Threat Level</strong></td><td>${scan.analysis.virustotal_threat_level}</td></tr>` : ''}
                    ${scan.analysis.virustotal_risk_score ? `<tr><td><strong>VirusTotal Risk Score</strong></td><td>${scan.analysis.virustotal_risk_score.toFixed(1)}%</td></tr>` : ''}
                    ${scan.analysis.javascript_risk_score ? `<tr><td><strong>JavaScript Risk Score</strong></td><td>${scan.analysis.javascript_risk_score.toFixed(1)}%</td></tr>` : ''}
                </tbody>
            </table>
        </section>
        ` : ''}

        <section class="recommendations">
            <h2>💡 Implications and Recommendations</h2>

            <h3>⏱️ Immediate Actions (1-24 hours)</h3>
            <ul>
                ${recommendationsData['Immediate Actions'] ? recommendationsData['Immediate Actions'].map(item => `<li>${item}</li>`).join('') : '<li>No immediate actions required</li>'}
            </ul>

            <h3>📅 Short-term Mitigations (1-7 days)</h3>
            <ul>
                ${recommendationsData['Short-term Mitigations'] ? recommendationsData['Short-term Mitigations'].map(item => `<li>${item}</li>`).join('') : '<li>Monitor for further developments</li>'}
            </ul>

            <h3>🎯 Long-term Strategy (1-3 months)</h3>
            <ul>
                ${recommendationsData['Long-term Strategy'] ? recommendationsData['Long-term Strategy'].map(item => `<li>${item}</li>`).join('') : '<li>Continue security assessments</li>'}
            </ul>
        </section>

        <footer style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; font-size: 12px;">
            <p>Report generated on ${new Date().toLocaleString()}</p>
            <p>MalwareSniffer Security Scan Report | Confidential</p>
        </footer>
    </div>
</body>
</html>
    `;

    return html;
  };

  downloadHTMLReport = (scan: ScanData): void => {
    const html = this.generateHTMLReport(scan);
    const blob = new Blob([html], { type: 'text/html' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `malware-sniffer-report-${scan.id}-${this.getTimestampForFilename()}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  };
}

export const reportGenerator = new ReportGenerator();
