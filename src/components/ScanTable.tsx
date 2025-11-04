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
      safe: "bg-success/20 text-success border-success/30",
      suspicious: "bg-warning/20 text-warning border-warning/30",
      malicious: "bg-destructive/20 text-destructive border-destructive/30",
    };

    return (
      <Badge variant="outline" className={variants[status as keyof typeof variants]}>
        {status.toUpperCase()}
      </Badge>
    );
  };

  return (
    <div className="rounded-lg border border-primary/20 bg-card overflow-hidden">
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent border-primary/20">
              <TableHead className="text-muted-foreground">Status</TableHead>
              <TableHead className="text-muted-foreground">URL</TableHead>
              <TableHead className="text-muted-foreground">Threat Score</TableHead>
              <TableHead className="text-muted-foreground">Timestamp</TableHead>
              <TableHead className="text-muted-foreground">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.map((scan) => (
              <TableRow
                key={scan.id}
                className="hover:bg-primary/5 border-primary/10 transition-colors"
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
                    <div className="w-16 h-2 bg-secondary rounded-full overflow-hidden">
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
                    <span className="text-sm font-mono">{scan.threatScore}%</span>
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
                    className="gap-1"
                  >
                    Details
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
