import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import ErrorBoundary from "./components/ErrorBoundary";
import Home from "./pages/Home";
import RealTimeDashboard from "./pages/RealTimeDashboard";
import SystemDebug from "./pages/SystemDebug";
import Blog from "./pages/Blog";
import UnifiedCyberNews from "./pages/UnifiedCyberNews";
import Feedback from "./pages/Feedback";
import Settings from "./pages/Settings";
import NotFound from "./pages/NotFound";
import RealTimeMonitor from "./components/RealTimeMonitor";
import CyberSecurityBlog from "./components/CyberSecurityBlog";
import ThreatAnalysis from "./components/ThreatAnalysis";
import LogViewer from "./components/LogViewer";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30000,
    },
  },
});

const App = () => (
  <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/dashboard" element={<RealTimeDashboard />} />
            <Route path="/debug" element={<SystemDebug />} />
            <Route path="/blogs" element={<Blog />} />
            <Route path="/cyber-news" element={<UnifiedCyberNews />} />
            <Route path="/feedback" element={<Feedback />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/monitor" element={<RealTimeMonitor />} />
            <Route path="/news" element={<CyberSecurityBlog />} />
            <Route path="/threats" element={<ThreatAnalysis />} />
            <Route path="/logs" element={<LogViewer />} />
            {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </ErrorBoundary>
);

export default App;
