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

const UnifiedCyberNews = () => {
  const [articles, setArticles] = useState<NewsArticle[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [isCached, setIsCached] = useState(false);
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const BACKEND_API = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";
  const AUTO_REFRESH_INTERVAL = 15 * 60 * 1000; // 15 minutes

  const fetchNews = async (isAutoRefresh = false) => {
    if (!isAutoRefresh) {
      setLoading(true);
      setError(null);
    }
    
    try {
      const res = await fetch(`${BACKEND_API}/api/cyber-news`);
      if (!res.ok) throw new Error(`Failed to fetch news: ${res.status}`);
      
      const data = await res.json();
      
      if (data.success && data.articles) {
        setArticles(data.articles);
        setLastUpdated(new Date());
        setIsCached(data.cached || false);
        
        if (data.fetch_errors && data.fetch_errors.length > 0) {
          console.warn("Some feeds failed to fetch:", data.fetch_errors);
        }
      } else {
        throw new Error(data.error || "Failed to load articles");
      }
    } catch (err: any) {
      console.error(err);
      if (!isAutoRefresh || !articles) {
        setError(err?.message || "Unable to load news");
      }
    } finally {
      if (!isAutoRefresh) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    // Initial fetch
    fetchNews();

    // Setup auto-refresh every 15 minutes
    refreshIntervalRef.current = setInterval(() => {
      fetchNews(true);
    }, AUTO_REFRESH_INTERVAL);

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, []);

  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString);
      const now = new Date();
      const diffInHours = (now.getTime() - date.getTime()) / (1000 * 60 * 60);
      
      if (diffInHours < 1) {
        return "Just now";
      } else if (diffInHours < 24) {
        return `${Math.floor(diffInHours)}h ago`;
      } else {
        return date.toLocaleDateString("en-US", {
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        });
      }
    } catch {
      return dateString;
    }
  };

  const getSourceColor = (source: string) => {
    const colors: { [key: string]: string } = {
      "Krebs on Security": "bg-blue-100 text-blue-800",
      "BleepingComputer": "bg-purple-100 text-purple-800",
      "The Hacker News": "bg-red-100 text-red-800",
      "Dark Reading": "bg-orange-100 text-orange-800",
    };
    return colors[source] || "bg-gray-100 text-gray-800";
  };

  const stripHtml = (html: string) => {
    const tmp = document.createElement("div");
    tmp.innerHTML = html;
    return tmp.textContent || tmp.innerText || "";
  };

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold tracking-tight flex items-center gap-2">
                <Rss className="w-10 h-10 text-primary" />
                Cybersecurity Blogs
              </h1>
              <p className="text-muted-foreground mt-2 text-lg">
                Latest news and insights from the cybersecurity community
              </p>
            </div>
            <Button 
              onClick={() => fetchNews()} 
              disabled={loading} 
              variant="outline" 
              size="lg"
              className="gap-2"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
          </div>

          {/* Last Updated Info */}
          <div className="flex items-center justify-between px-4 py-3 bg-muted rounded-lg">
            <div className="text-sm">
              {lastUpdated && (
                <span className="text-muted-foreground">
                  Last updated: {lastUpdated.toLocaleTimeString()} 
                  {isCached && <span className="ml-2 text-xs text-yellow-600">(cached)</span>}
                </span>
              )}
            </div>
            <div className="text-sm font-medium">
              {articles && <span>{articles.length} articles</span>}
            </div>
          </div>
        </div>

        {/* Error State */}
        {error && !articles && (
          <Card className="border-destructive bg-destructive/5">
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
                <CardHeader>
                  <Skeleton className="h-6 w-3/4 mb-2" />
                  <Skeleton className="h-4 w-1/2" />
                </CardHeader>
                <CardContent>
                  <Skeleton className="h-20 w-full" />
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Articles List */}
        {!loading && articles && articles.length > 0 && (
          <div className="space-y-4">
            {articles.map((article, idx) => (
              <Card 
                key={idx} 
                className="hover:shadow-md transition-shadow border-l-4 border-l-primary"
              >
                <CardHeader>
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <CardTitle className="text-lg leading-tight mb-2">
                          {article.title}
                        </CardTitle>
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge className={`${getSourceColor(article.source)} font-semibold`}>
                            {article.source}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {formatDate(article.pubDate)}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="space-y-4">
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {stripHtml(article.contentSnippet)}
                  </p>

                  <Button 
                    asChild 
                    variant="default" 
                    size="sm"
                    className="w-full gap-2"
                  >
                    <a 
                      href={article.link} 
                      target="_blank" 
                      rel="noopener noreferrer"
                    >
                      Read Full Article
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Empty State */}
        {!loading && articles && articles.length === 0 && (
          <Card className="border-dashed">
            <CardContent className="pt-8 text-center">
              <p className="text-muted-foreground font-semibold">No articles found</p>
              <p className="text-sm text-muted-foreground mt-1">
                Try refreshing in a few moments
              </p>
            </CardContent>
          </Card>
        )}

        {/* Info Footer */}
        <div className="text-xs text-muted-foreground text-center pt-4 border-t">
          <p>
            Aggregating news from Krebs on Security, BleepingComputer, The Hacker News, and Dark Reading.
            <br />
            Auto-refreshes every 15 minutes. Last refresh: {lastUpdated?.toLocaleTimeString()}
          </p>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default UnifiedCyberNews;
