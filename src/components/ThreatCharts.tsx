import { PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from "recharts";

const ThreatCharts = () => {
  const scanDistributionData = [
    { name: "Safe", value: 842, color: "hsl(150 100% 45%)" },
    { name: "Suspicious", value: 124, color: "hsl(45 100% 60%)" },
    { name: "Malicious", value: 34, color: "hsl(0 100% 60%)" },
  ];

  const threatTrendData = [
    { date: "Mon", threats: 12 },
    { date: "Tue", threats: 8 },
    { date: "Wed", threats: 15 },
    { date: "Thu", threats: 6 },
    { date: "Fri", threats: 11 },
    { date: "Sat", threats: 9 },
    { date: "Sun", threats: 7 },
  ];

  const topDomainsData = [
    { domain: "malware-site.com", count: 8 },
    { domain: "phishing-bank.net", count: 6 },
    { domain: "fake-update.org", count: 5 },
    { domain: "spam-ads.biz", count: 4 },
    { domain: "suspicious.io", count: 3 },
  ];

  return (
    <div className="grid lg:grid-cols-3 gap-6">
      {/* Scan Distribution Pie Chart */}
      <div className="p-6 rounded-lg bg-card border border-primary/20">
        <h3 className="text-lg font-orbitron font-bold mb-4">Scan Distribution</h3>
        <ResponsiveContainer width="100%" height={250}>
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
                backgroundColor: "hsl(220 35% 12%)",
                border: "1px solid hsl(180 100% 50% / 0.3)",
                borderRadius: "8px",
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Threat Trend Line Chart */}
      <div className="p-6 rounded-lg bg-card border border-primary/20">
        <h3 className="text-lg font-orbitron font-bold mb-4">Weekly Threat Trend</h3>
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={threatTrendData}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(180 100% 50% / 0.1)" />
            <XAxis dataKey="date" stroke="hsl(180 100% 95%)" />
            <YAxis stroke="hsl(180 100% 95%)" />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(220 35% 12%)",
                border: "1px solid hsl(180 100% 50% / 0.3)",
                borderRadius: "8px",
              }}
            />
            <Line
              type="monotone"
              dataKey="threats"
              stroke="hsl(0 100% 60%)"
              strokeWidth={2}
              dot={{ fill: "hsl(0 100% 60%)" }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Top Malicious Domains Bar Chart */}
      <div className="p-6 rounded-lg bg-card border border-primary/20">
        <h3 className="text-lg font-orbitron font-bold mb-4">Top Malicious Domains</h3>
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={topDomainsData} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(180 100% 50% / 0.1)" />
            <XAxis type="number" stroke="hsl(180 100% 95%)" />
            <YAxis
              dataKey="domain"
              type="category"
              width={120}
              stroke="hsl(180 100% 95%)"
              tick={{ fontSize: 10 }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(220 35% 12%)",
                border: "1px solid hsl(180 100% 50% / 0.3)",
                borderRadius: "8px",
              }}
            />
            <Bar dataKey="count" fill="hsl(45 100% 60%)" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default ThreatCharts;
