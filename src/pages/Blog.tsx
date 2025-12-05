import { useState, useEffect, useRef } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { ExternalLink, RefreshCw, Rss } from "lucide-react";

type NewsArticle = {
  title: string;
  link: string;
  pubDate: string;
  contentSnippet: string;
  source: string;
};

const Blog = () => {
  const [articles, setArticles] = useState<NewsArticle[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isCached, setIsCached] = useState(false);
  const [isLive, setIsLive] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const BACKEND_API = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";

  // Fetch live news immediately
  const fetchLiveNews = async () => {
    setLoading(true);
    setError(null);
    setIsLive(true);
    
    try {
      const timestamp = Date.now();
      const res = await fetch(`${BACKEND_API}/api/news/live?t=${timestamp}`);
      
      if (!res.ok) throw new Error(`Failed to fetch news: ${res.status}`);
      
      const data = await res.json();
      
      if (data.success && data.articles) {
        setArticles(data.articles);
        setLastUpdated(new Date());
        setIsCached(false);
      } else {
        throw new Error(data.error || "Failed to load articles");
      }
    } catch (err: any) {
      console.error("Error fetching live news:", err);
      setError(err?.message || "Unable to load news");
      setArticles(null);
    } finally {
      setLoading(false);
    }
  };

  // Connect to SSE stream for automatic updates
  const connectToSSEStream = () => {
    try {
      // Close existing connection if any
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }

      console.log("🔴 Connecting to live news SSE stream...");
      eventSourceRef.current = new EventSource(`${BACKEND_API}/api/news/stream`);

      eventSourceRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.articles) {
            setArticles(data.articles);
            setLastUpdated(new Date());
            setIsLive(true);
            console.log(`🔴 SSE Update: ${data.articles.length} articles received`);
          }
        } catch (e) {
          console.error("Error parsing SSE data:", e);
        }
      };

      eventSourceRef.current.onerror = (error) => {
        console.error("SSE Connection error:", error);
        if (eventSourceRef.current) {
          eventSourceRef.current.close();
          eventSourceRef.current = null;
        }
        // Retry connection after 5 seconds
        setTimeout(connectToSSEStream, 5000);
      };
    } catch (err) {
      console.error("Failed to connect to SSE stream:", err);
      // Retry after 5 seconds
      setTimeout(connectToSSEStream, 5000);
    }
  };

  useEffect(() => {
    // Fetch live news immediately on load
    fetchLiveNews();
    
    // Connect to SSE stream for automatic updates every 30 minutes
    connectToSSEStream();
    
    return () => {
      // Cleanup on unmount
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, []);

  const getSourceColor = (source: string): string => {
    const sourceColors: { [key: string]: string } = {
      "Krebs on Security": "bg-blue-100 text-blue-800",
      "BleepingComputer": "bg-purple-100 text-purple-800",
      "The Hacker News": "bg-red-100 text-red-800",
      "Dark Reading": "bg-orange-100 text-orange-800",
    };
    return sourceColors[source] || "bg-gray-100 text-gray-800";
  };

  const formatTime = (pubDate: string): string => {
    try {
      const date = new Date(pubDate);
      const now = new Date();
      const diffMs = now.getTime() - date.getTime();
      const diffMins = Math.floor(diffMs / (1000 * 60));
      const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

      if (diffMins < 1) return "Just now";
      if (diffMins < 60) return `${diffMins}m ago`;
      if (diffHours < 24) return `${diffHours}h ago`;
      if (diffDays < 7) return `${diffDays}d ago`;

      return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
    } catch {
      return new Date(pubDate).toLocaleDateString();
    }
  };

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <Rss className="w-8 h-8 text-primary" />
              <h1 className="text-3xl font-bold tracking-tight">Cybersecurity Blogs</h1>
            </div>
            <p className="text-muted-foreground">
              Latest news and insights from the cybersecurity community
            </p>
            {lastUpdated && (
              <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                <p>Last updated: {lastUpdated.toLocaleTimeString()}</p>
              </div>
            )}
          </div>
          <Button onClick={() => fetchLiveNews()} disabled={loading} variant="outline" size="sm">
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>

        {/* Article Count */}
        {articles && (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">
              <span className={`font-semibold ${isLive ? 'text-red-600 animate-pulse' : 'text-green-600'}`}>
                {isLive ? '🔴 LIVE STREAMING' : '✅ LIVE'}
              </span> - Showing {articles.length} fresh articles from real-time cybersecurity sources
            </p>
            <p className="text-xs text-muted-foreground">
              Auto-updates every 30 minutes via server-sent events (SSE)
            </p>
          </div>
        )}

        {/* Error State */}
        {error && (
          <Card className="border-destructive">
            <CardContent className="pt-6">
              <div className="text-center text-destructive">
                <p className="font-semibold">Failed to load news</p>
                <p className="text-sm mt-1">{error}</p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Loading State */}
        {loading && !articles && (
          <div className="space-y-4">
            {[1, 2, 3, 4].map((i) => (
              <Card key={i}>
                <CardContent className="pt-6">
                  <Skeleton className="h-6 w-3/4 mb-3" />
                  <Skeleton className="h-4 w-1/2 mb-3" />
                  <Skeleton className="h-12 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Articles List */}
        {!loading && !error && articles && articles.length > 0 && (
          <div className="space-y-4">
            {articles.map((article, idx) => (
              <Card key={idx} className="hover:shadow-md transition-shadow">
                <CardContent className="pt-6">
                  <div className="space-y-3">
                    {/* Title and Source Badge */}
                    <div className="flex items-start justify-between gap-3">
                      <h3 className="text-lg font-semibold leading-tight flex-1 line-clamp-2">
                        {article.title}
                      </h3>
                      <Badge className={`whitespace-nowrap text-xs flex-shrink-0 ${getSourceColor(article.source)}`}>
                        {article.source}
                      </Badge>
                    </div>

                    {/* Meta Information */}
                    <p className="text-xs text-muted-foreground">
                      {formatTime(article.pubDate)}
                    </p>

                    {/* Content Snippet */}
                    <p className="text-sm text-muted-foreground line-clamp-3">
                      {article.contentSnippet}
                    </p>

                    {/* Read More Link */}
                    <a
                      href={article.link}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
                    >
                      Read More
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Empty State */}
        {!loading && !error && articles && articles.length === 0 && (
          <Card>
            <CardContent className="pt-6">
              <div className="text-center text-muted-foreground">
                <p className="font-semibold">No articles found</p>
                <p className="text-sm mt-1">Try refreshing or check back later</p>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </DashboardLayout>
  );
};

export default Blog;
