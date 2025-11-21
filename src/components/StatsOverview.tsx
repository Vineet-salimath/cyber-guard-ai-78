// ═══════════════════════════════════════════════════════════════════════════
// STATS OVERVIEW - Real-time statistics dashboard
// ═══════════════════════════════════════════════════════════════════════════

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, AlertTriangle, Activity, TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface StatsOverviewProps {
  stats: {
    total: number;
    safe: number;
    suspicious: number;
    malicious: number;
    detectionRate?: number;
  };
  isLive?: boolean;
}

export const StatsOverview = ({ stats, isLive = false }: StatsOverviewProps) => {
  const detectionRate = stats.detectionRate ?? 
    (stats.total > 0 ? ((stats.safe / stats.total) * 100) : 0);

  const getTrendIcon = (value: number) => {
    if (value === 0) return <Minus className="h-4 w-4 text-muted-foreground" />;
    if (value > 0) return <TrendingUp className="h-4 w-4 text-green-600" />;
    return <TrendingDown className="h-4 w-4 text-red-600" />;
  };

  const statCards = [
    {
      title: 'Total Scans',
      value: stats.total,
      icon: Activity,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      trend: '+Live'
    },
    {
      title: 'Safe Sites',
      value: stats.safe,
      icon: Shield,
      color: 'text-green-600',
      bgColor: 'bg-green-50',
      percentage: stats.total > 0 ? ((stats.safe / stats.total) * 100).toFixed(1) + '%' : '0%'
    },
    {
      title: 'Suspicious',
      value: stats.suspicious,
      icon: AlertTriangle,
      color: 'text-orange-600',
      bgColor: 'bg-orange-50',
      percentage: stats.total > 0 ? ((stats.suspicious / stats.total) * 100).toFixed(1) + '%' : '0%'
    },
    {
      title: 'Malicious',
      value: stats.malicious,
      icon: AlertTriangle,
      color: 'text-red-600',
      bgColor: 'bg-red-50',
      percentage: stats.total > 0 ? ((stats.malicious / stats.total) * 100).toFixed(1) + '%' : '0%'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {statCards.map((stat, index) => {
        const Icon = stat.icon;
        return (
          <Card key={index} className="relative overflow-hidden">
            {isLive && index === 0 && (
              <div className="absolute top-2 right-2">
                <span className="flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                </span>
              </div>
            )}
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground flex items-center justify-between">
                {stat.title}
                <div className={`p-2 rounded-lg ${stat.bgColor}`}>
                  <Icon className={`h-4 w-4 ${stat.color}`} />
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline justify-between">
                <div className="text-3xl font-bold">{stat.value}</div>
                {stat.percentage && (
                  <div className="text-sm text-muted-foreground font-semibold">
                    {stat.percentage}
                  </div>
                )}
                {stat.trend && (
                  <div className="text-xs text-green-600 font-semibold flex items-center gap-1">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                    </span>
                    {stat.trend}
                  </div>
                )}
              </div>
              {index === 0 && (
                <div className="mt-2 text-xs text-muted-foreground">
                  Detection Rate: <span className="font-semibold">{detectionRate.toFixed(1)}%</span>
                </div>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
};

export default StatsOverview;
