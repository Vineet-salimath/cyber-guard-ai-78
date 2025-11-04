import { Shield, AlertTriangle, XCircle, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

interface Scan {
  id: string;
  url: string;
  timestamp: string;
  status: "safe" | "suspicious" | "malicious";
  threatScore: number;
}

interface ScanTableProps {
  scans: Scan[];
  onViewDetails: (scan: Scan) => void;
}

const ScanTable = ({ scans, onViewDetails }: ScanTableProps) => {
  const getStatusIcon = (status: string) => {
    switch (status) {
      case "safe":
        return <Shield className="w-4 h-4 text-success" />;
      case "suspicious":
        return <AlertTriangle className="w-4 h-4 text-warning" />;
      case "malicious":
        return <XCircle className="w-4 h-4 text-destructive" />;
      default:
        return null;
    }
  };

  const getStatusBadge = (status: string) => {
    const variants = {
      safe: "bg-success/10 text-success border-success/20 hover:bg-success/20",
      suspicious: "bg-warning/10 text-warning border-warning/20 hover:bg-warning/20",
      malicious: "bg-destructive/10 text-destructive border-destructive/20 hover:bg-destructive/20",
    };

    return (
      <Badge variant="outline" className={`${variants[status as keyof typeof variants]} font-medium`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </Badge>
    );
  };

  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent border-b">
              <TableHead className="font-medium">Status</TableHead>
              <TableHead className="font-medium">URL</TableHead>
              <TableHead className="font-medium">Threat Score</TableHead>
              <TableHead className="font-medium">Timestamp</TableHead>
              <TableHead className="font-medium">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.map((scan) => (
              <TableRow
                key={scan.id}
                className="hover:bg-muted/50 transition-colors"
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(scan.status)}
                    {getStatusBadge(scan.status)}
                  </div>
                </TableCell>
                <TableCell className="max-w-md truncate font-mono text-sm">
                  {scan.url}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-2 bg-secondary rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all ${
                          scan.threatScore > 70
                            ? "bg-destructive"
                            : scan.threatScore > 40
                            ? "bg-warning"
                            : "bg-success"
                        }`}
                        style={{ width: `${scan.threatScore}%` }}
                      />
                    </div>
                    <span className="text-sm font-mono tabular-nums">{scan.threatScore}%</span>
                  </div>
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {scan.timestamp}
                </TableCell>
                <TableCell>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onViewDetails(scan)}
                    className="gap-1 h-8"
                  >
                    <span className="text-xs">Details</span>
                    <ExternalLink className="w-3 h-3" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
};

export default ScanTable;
