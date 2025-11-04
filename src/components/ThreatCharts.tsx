import { PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from "recharts";

const ThreatCharts = () => {
  const scanDistributionData = [
    { name: "Safe", value: 842, color: "hsl(142 76% 36%)" },
    { name: "Suspicious", value: 124, color: "hsl(38 92% 50%)" },
    { name: "Malicious", value: 34, color: "hsl(0 84% 60%)" },
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
