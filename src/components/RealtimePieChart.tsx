// REALTIME PIE CHART - Shows Benign%, Suspicious%, Malicious% distribution
// Updates instantly when new scans arrive

import { useEffect, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

interface ScanStats {
  benign_count: number;
  suspicious_count: number;
  malicious_count: number;
  total_scans: number;
  benign_percentage: number;
  suspicious_percentage: number;
  malicious_percentage: number;
}

interface RealtimePieChartProps {
  stats: ScanStats;
}

const COLORS = {
  benign: '#10b981',      // Green
  suspicious: '#f59e0b',  // Orange
  malicious: '#ef4444'    // Red
};

const RealtimePieChart = ({ stats }: RealtimePieChartProps) => {
  const prevStatsRef = useRef<ScanStats | null>(null);
  const chartRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Animate when stats change
    if (prevStatsRef.current && chartRef.current) {
      const changed = 
        prevStatsRef.current.total_scans !== stats.total_scans ||
        prevStatsRef.current.benign_count !== stats.benign_count ||
        prevStatsRef.current.suspicious_count !== stats.suspicious_count ||
        prevStatsRef.current.malicious_count !== stats.malicious_count;

      if (changed) {
        chartRef.current.classList.add('animate-pulse');
        setTimeout(() => {
          chartRef.current?.classList.remove('animate-pulse');
        }, 500);
      }
    }
    prevStatsRef.current = stats;
  }, [stats]);

  // Prepare data for pie chart
  const data = [
    {
      name: 'Benign',
      value: stats.benign_count,
      percentage: stats.benign_percentage,
      color: COLORS.benign
    },
    {
      name: 'Suspicious',
      value: stats.suspicious_count,
      percentage: stats.suspicious_percentage,
      color: COLORS.suspicious
    },
    {
      name: 'Malicious',
      value: stats.malicious_count,
      percentage: stats.malicious_percentage,
      color: COLORS.malicious
    }
  ].filter(item => item.value > 0); // Only show categories with data

  // Custom label
  const renderCustomLabel = (entry: any) => {
    return `${entry.percentage.toFixed(1)}%`;
  };

  // Custom tooltip
  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-white dark:bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <p className="font-semibold text-gray-900 dark:text-white">{data.name}</p>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Count: <span className="font-bold">{data.value}</span>
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Percentage: <span className="font-bold">{data.percentage.toFixed(1)}%</span>
          </p>
        </div>
      );
    }
    return null;
  };

  if (stats.total_scans === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Scan Distribution</CardTitle>
          <CardDescription>No scans performed yet</CardDescription>
        </CardHeader>
        <CardContent className="h-64 flex items-center justify-center">
          <p className="text-gray-400 text-sm">Waiting for scan data...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card ref={chartRef} className="transition-all duration-300">
      <CardHeader>
        <CardTitle>Scan Distribution</CardTitle>
        <CardDescription>
          Real-time threat categorization • {stats.total_scans} total scans
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={renderCustomLabel}
              outerRadius={100}
              fill="#8884d8"
              dataKey="value"
              animationBegin={0}
              animationDuration={800}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
            <Legend 
              verticalAlign="bottom" 
              height={36}
              formatter={(value, entry: any) => (
                <span style={{ color: entry.color }}>
                  {value}: {entry.payload.value}
                </span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>

        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-4 mt-4">
          <div className="text-center p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {stats.benign_percentage.toFixed(1)}%
            </div>
            <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">
              Benign Sites
            </div>
            <div className="text-sm font-semibold text-gray-800 dark:text-gray-200">
              {stats.benign_count}
            </div>
          </div>

          <div className="text-center p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {stats.suspicious_percentage.toFixed(1)}%
            </div>
            <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">
              Suspicious
            </div>
            <div className="text-sm font-semibold text-gray-800 dark:text-gray-200">
              {stats.suspicious_count}
            </div>
          </div>

          <div className="text-center p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
            <div className="text-2xl font-bold text-red-600 dark:text-red-400">
              {stats.malicious_percentage.toFixed(1)}%
            </div>
            <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">
              Malicious
            </div>
            <div className="text-sm font-semibold text-gray-800 dark:text-gray-200">
              {stats.malicious_count}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default RealtimePieChart;
