import { useState, useEffect } from "react";
import { PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from "recharts";

const ThreatCharts = () => {
  const [scanDistributionData, setScanDistributionData] = useState([
    { name: "Safe", value: 0, color: "hsl(142 76% 36%)" },
    { name: "Suspicious", value: 0, color: "hsl(38 92% 50%)" },
    { name: "Malicious", value: 0, color: "hsl(0 84% 60%)" },
  ]);

  const [topDomainsData, setTopDomainsData] = useState([
    { domain: "Loading...", count: 0 },
  ]);

  const [threatTrendData, setThreatTrendData] = useState([
    { date: "Mon", threats: 0 },
    { date: "Tue", threats: 0 },
    { date: "Wed", threats: 0 },
    { date: "Thu", threats: 0 },
    { date: "Fri", threats: 0 },
    { date: "Sat", threats: 0 },
    { date: "Sun", threats: 0 },
  ]);

  useEffect(() => {
    fetchChartData();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchChartData, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchChartData = async () => {
    try {
      // Fetch threat statistics from backend
      const response = await fetch('http://localhost:5000/api/threat-statistics');
      const data = await response.json();

      // Update scan distribution pie chart
      setScanDistributionData([
        { name: "Safe", value: data.severity_breakdown.SAFE || 0, color: "hsl(142 76% 36%)" },
        { name: "Suspicious", value: data.severity_breakdown.MEDIUM || 0, color: "hsl(38 92% 50%)" },
        { name: "Malicious", value: data.severity_breakdown.CRITICAL || 0, color: "hsl(0 84% 60%)" },
      ]);

      // Update top domains bar chart
      if (data.top_domains && data.top_domains.length > 0) {
        setTopDomainsData(
          data.top_domains.slice(0, 5).map((item: any) => ({
            domain: item.domain,
            count: item.count
          }))
        );
      }

      console.log('✅ Chart data updated from backend API');

      // Fetch weekly threat trend from backend
      try {
        const trendResponse = await fetch('http://localhost:5000/api/weekly-threat-trend');
        const trendData = await trendResponse.json();
        
        if (Array.isArray(trendData) && trendData.length > 0) {
          setThreatTrendData(trendData);
          console.log('✅ Weekly threat trend updated from real-time analysis:', trendData);
        } else {
          console.log('⚠️  No weekly trend data available - using empty data');
        }
      } catch (trendError) {
        console.error('❌ Error fetching weekly trend:', trendError);
      }
      
    } catch (error) {
      console.error('❌ Error fetching chart data:', error);
    }
  };

  return (
    <div className="grid lg:grid-cols-3 gap-6">
      {/* Scan Distribution Pie Chart */}
      <div className="p-6 rounded-xl bg-card border">
        <h3 className="text-base font-semibold mb-6">Scan Distribution</h3>
        <ResponsiveContainer width="100%" height={240}>
          <PieChart>
            <Pie
              data={scanDistributionData}
              cx="50%"
              cy="50%"
              labelLine={false}
              label
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
            >
              {scanDistributionData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontSize: "14px",
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Threat Trend Line Chart */}
      <div className="p-6 rounded-xl bg-card border">
        <h3 className="text-base font-semibold mb-6">Weekly Threat Trend</h3>
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={threatTrendData}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis dataKey="date" stroke="hsl(var(--muted-foreground))" fontSize={12} />
            <YAxis stroke="hsl(var(--muted-foreground))" fontSize={12} />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontSize: "14px",
              }}
            />
            <Line
              type="monotone"
              dataKey="threats"
              stroke="hsl(var(--destructive))"
              strokeWidth={2}
              dot={{ fill: "hsl(var(--destructive))", r: 4 }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Top Malicious Domains Bar Chart */}
      <div className="p-6 rounded-xl bg-card border">
        <h3 className="text-base font-semibold mb-6">Top Malicious Domains</h3>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={topDomainsData} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis type="number" stroke="hsl(var(--muted-foreground))" fontSize={12} />
            <YAxis
              dataKey="domain"
              type="category"
              width={120}
              stroke="hsl(var(--muted-foreground))"
              tick={{ fontSize: 11 }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontSize: "14px",
              }}
            />
            <Bar dataKey="count" fill="hsl(var(--warning))" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default ThreatCharts;
