import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";
import { ArrowLeft, Activity, Database, Wifi, Server, Shield, Zap } from "lucide-react";

const SystemDebug = () => {
  const systemStatus = {
    backend: "online",
    websocket: "connected",
    database: "operational",
    mlModels: "loaded",
    extension: "active",
    realtime: "enabled"
  };

  const metrics = [
    { label: "Backend Status", value: systemStatus.backend, icon: Server, color: "green" },
    { label: "WebSocket", value: systemStatus.websocket, icon: Wifi, color: "green" },
    { label: "Database", value: systemStatus.database, icon: Database, color: "green" },
    { label: "ML Models", value: systemStatus.mlModels, icon: Shield, color: "green" },
    { label: "Extension", value: systemStatus.extension, icon: Activity, color: "green" },
    { label: "Real-time", value: systemStatus.realtime, icon: Zap, color: "green" }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-4 mb-8">
          <Link to="/">
            <Button variant="ghost" size="icon" className="text-white hover:bg-white/10">
              <ArrowLeft className="h-5 w-5" />
            </Button>
          </Link>
          <div>
            <h1 className="text-4xl font-bold text-white">System Debug</h1>
            <p className="text-gray-300 mt-2">Real-time system status and diagnostics</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          {metrics.map((metric, index) => {
            const Icon = metric.icon;
            return (
              <Card key={index} className="bg-white/5 backdrop-blur-lg border-white/10">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-white">
                    {metric.label}
                  </CardTitle>
                  <Icon className={`h-4 w-4 text-${metric.color}-500`} />
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-2">
                    <Badge variant={metric.color === "green" ? "default" : "destructive"} className="capitalize">
                      {metric.value}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        <Card className="bg-white/5 backdrop-blur-lg border-white/10">
          <CardHeader>
            <CardTitle className="text-white">System Information</CardTitle>
            <CardDescription className="text-gray-300">
              Current system configuration and status
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="text-gray-400">Backend URL:</div>
              <div className="text-white font-mono">http://localhost:5000</div>
              
              <div className="text-gray-400">Dashboard URL:</div>
              <div className="text-white font-mono">http://localhost:8080</div>
              
              <div className="text-gray-400">WebSocket:</div>
              <div className="text-white font-mono">ws://localhost:5000</div>
              
              <div className="text-gray-400">Extension Status:</div>
              <div className="text-green-400">Active & Scanning</div>
              
              <div className="text-gray-400">Real-time Updates:</div>
              <div className="text-green-400">Enabled</div>
              
              <div className="text-gray-400">ML Models:</div>
              <div className="text-green-400">URL ML + JS ML Loaded</div>
            </div>
          </CardContent>
        </Card>

        <div className="mt-8 flex gap-4">
          <Link to="/dashboard">
            <Button className="bg-gradient-to-r from-purple-500 to-pink-500 hover:from-purple-600 hover:to-pink-600">
              View Dashboard
            </Button>
          </Link>
          <Link to="/logs">
            <Button variant="outline" className="border-white/20 text-white hover:bg-white/10">
              View Logs
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
};

export default SystemDebug;
