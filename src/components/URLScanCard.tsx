// ═══════════════════════════════════════════════════════════════════════════
// URL SCAN CARD - Detailed scan information popup
// ═══════════════════════════════════════════════════════════════════════════

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { AlertTriangle, Shield, Info, ExternalLink, Clock, Activity } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';

interface ScanDetails {
  id: string | number;
  url: string;
  timestamp: string | number;
  status: string;
  threatScore: number;
  classification?: string;
  indicators?: string[];
  method?: string;
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

interface URLScanCardProps {
  scan: ScanDetails | null;
  isOpen: boolean;
  onClose: () => void;
}

export const URLScanCard = ({ scan, isOpen, onClose }: URLScanCardProps) => {
  if (!scan) return null;

  const getThreatColor = (score: number) => {
    if (score >= 70) return 'text-red-600 bg-red-50 border-red-200';
    if (score >= 40) return 'text-orange-600 bg-orange-50 border-orange-200';
    return 'text-green-600 bg-green-50 border-green-200';
  };

  const getThreatIcon = (score: number) => {
    if (score >= 70) return <AlertTriangle className="h-8 w-8 text-red-600" />;
    if (score >= 40) return <Info className="h-8 w-8 text-orange-600" />;
    return <Shield className="h-8 w-8 text-green-600" />;
  };

  const formatTimestamp = (timestamp: string | number) => {
    try {
      const date = typeof timestamp === 'number' ? new Date(timestamp) : new Date(timestamp);
      return date.toLocaleString();
    } catch {
      return 'Unknown';
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {getThreatIcon(scan.threatScore)}
            Scan Details - #{scan.id}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          {/* URL and Status */}
          <Card className={getThreatColor(scan.threatScore) + ' border-2'}>
            <CardHeader>
              <CardTitle className="text-lg flex items-center justify-between">
                <span>Risk Assessment</span>
                <Badge variant="outline" className="text-lg font-bold">
                  {scan.threatScore.toFixed(1)}%
                </Badge>
              </CardTitle>
              <CardDescription className="break-all">{scan.url}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-muted-foreground">Classification</div>
                  <div className="font-semibold text-lg">
                    {scan.classification || scan.status}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground">Method</div>
                  <div className="font-semibold">{scan.method || 'GET'}</div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground">Scanned At</div>
                  <div className="font-semibold flex items-center gap-1">
                    <Clock className="h-4 w-4" />
                    {formatTimestamp(scan.timestamp)}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground">Scan ID</div>
                  <div className="font-mono font-semibold">{scan.id}</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Threat Indicators */}
          {scan.indicators && scan.indicators.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Threat Indicators</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {scan.indicators.map((indicator, idx) => (
                    <Badge key={idx} variant="outline" className="text-sm">
                      <AlertTriangle className="h-3 w-3 mr-1" />
                      {indicator}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Analysis Breakdown */}
          {scan.analysis && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Analysis Breakdown
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {scan.analysis.ml_prediction && (
                    <div className="flex justify-between items-center p-2 bg-muted rounded">
                      <span className="text-sm font-medium">ML Prediction</span>
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary">{scan.analysis.ml_prediction}</Badge>
                        <span className="text-sm font-semibold">
                          {scan.analysis.ml_confidence?.toFixed(1)}% confidence
                        </span>
                      </div>
                    </div>
                  )}

                  {scan.analysis.virustotal_threat_level && (
                    <div className="flex justify-between items-center p-2 bg-muted rounded">
                      <span className="text-sm font-medium">VirusTotal</span>
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary">{scan.analysis.virustotal_threat_level}</Badge>
                        <span className="text-sm font-semibold">
                          Risk: {scan.analysis.virustotal_risk_score?.toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  )}

                  {scan.analysis.javascript_risk_score !== undefined && (
                    <div className="flex justify-between items-center p-2 bg-muted rounded">
                      <span className="text-sm font-medium">JavaScript Analysis</span>
                      <span className="text-sm font-semibold">
                        Risk: {scan.analysis.javascript_risk_score.toFixed(1)}%
                      </span>
                    </div>
                  )}

                  {scan.analysis.pattern_risk_score !== undefined && (
                    <div className="flex justify-between items-center p-2 bg-muted rounded">
                      <span className="text-sm font-medium">Suspicious Patterns</span>
                      <span className="text-sm font-semibold">
                        Risk: {scan.analysis.pattern_risk_score.toFixed(1)}%
                      </span>
                    </div>
                  )}

                  {scan.analysis.page_risk_score !== undefined && (
                    <div className="flex justify-between items-center p-2 bg-muted rounded">
                      <span className="text-sm font-medium">Page Characteristics</span>
                      <span className="text-sm font-semibold">
                        Risk: {scan.analysis.page_risk_score.toFixed(1)}%
                      </span>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Technical Details */}
          {scan.details && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Technical Details</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  {scan.details.has_obfuscated_js !== undefined && (
                    <div className="flex justify-between p-2 bg-muted rounded">
                      <span>Obfuscated JavaScript</span>
                      <Badge variant={scan.details.has_obfuscated_js ? "destructive" : "secondary"}>
                        {scan.details.has_obfuscated_js ? 'Yes' : 'No'}
                      </Badge>
                    </div>
                  )}

                  {scan.details.has_suspicious_patterns !== undefined && (
                    <div className="flex justify-between p-2 bg-muted rounded">
                      <span>Suspicious Patterns</span>
                      <Badge variant={scan.details.has_suspicious_patterns ? "destructive" : "secondary"}>
                        {scan.details.has_suspicious_patterns ? 'Detected' : 'None'}
                      </Badge>
                    </div>
                  )}

                  {scan.details.has_password_fields !== undefined && (
                    <div className="flex justify-between p-2 bg-muted rounded">
                      <span>Password Fields</span>
                      <Badge variant={scan.details.has_password_fields ? "outline" : "secondary"}>
                        {scan.details.has_password_fields ? 'Present' : 'None'}
                      </Badge>
                    </div>
                  )}

                  {scan.details.external_scripts_count !== undefined && (
                    <div className="flex justify-between p-2 bg-muted rounded">
                      <span>External Scripts</span>
                      <Badge variant="secondary">
                        {scan.details.external_scripts_count}
                      </Badge>
                    </div>
                  )}

                  {scan.details.iframe_count !== undefined && (
                    <div className="flex justify-between p-2 bg-muted rounded">
                      <span>Iframes</span>
                      <Badge variant="secondary">
                        {scan.details.iframe_count}
                      </Badge>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default URLScanCard;
