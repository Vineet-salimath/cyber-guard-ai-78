// ═══════════════════════════════════════════════════════════════════════════
// RISK GRAPH - Real-time threat visualization
// ═══════════════════════════════════════════════════════════════════════════

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { TrendingUp, PieChart as PieChartIcon } from 'lucide-react';

interface RiskGraphProps {
  stats: {
    total: number;
    safe: number;
    suspicious: number;
    malicious: number;
  };
  timelineData?: Array<{
    time: string;
    threats: number;
  }>;
}

export const RiskGraph = ({ stats, timelineData }: RiskGraphProps) => {
  // Prepare pie chart data
  const pieData = [
    { name: 'Safe', value: stats.safe, color: '#22c55e' },
    { name: 'Suspicious', value: stats.suspicious, color: '#f59e0b' },
    { name: 'Malicious', value: stats.malicious, color: '#ef4444' }
  ].filter(item => item.value > 0);

  // Prepare bar chart data
  const barData = [
    { category: 'Safe', count: stats.safe, fill: '#22c55e' },
    { category: 'Suspicious', count: stats.suspicious, fill: '#f59e0b' },
    { category: 'Malicious', count: stats.malicious, fill: '#ef4444' }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Threat Distribution Pie Chart */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <PieChartIcon className="h-4 w-4" />
            Threat Distribution
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={(entry) => `${entry.name}: ${entry.value}`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
          {stats.total === 0 && (
            <div className="text-center text-muted-foreground py-8">
              No data available yet
            </div>
          )}
        </CardContent>
      </Card>

      {/* Threat Category Bar Chart */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <TrendingUp className="h-4 w-4" />
            Category Breakdown
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={barData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="category" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                {barData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
};

export default RiskGraph;
