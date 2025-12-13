import { useState, useEffect, useRef } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { ExternalLink, RefreshCw, Rss } from "lucide-react";

type NewsArticle = {
  title: string;
  url: string;
  publishedAt: string;
  description: string;
  source: {
    name: string;
    category: string;
    icon?: string;
  } | string;
  image?: string;
  urlToImage?: string;
  author?: string;
};

const UnifiedCyberNews = () => {
  const [articles, setArticles] = useState<NewsArticle[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [category, setCategory] = useState<string>("all");
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Try RSS server first, fall back to Flask backend
  const RSS_API = "http://localhost:3001";
  const BACKEND_API = import.meta.env.VITE_BACKEND_URL || "http://localhost:5000";
  const AUTO_REFRESH_INTERVAL = 10 * 60 * 1000; // 10 minutes

  const fetchNews = async (isAutoRefresh = false) => {
    if (!isAutoRefresh) {
      setLoading(true);
      setError(null);
    }
    
    try {
      // Try RSS server first
      let data;
      let useRss = false;
      
      try {
        const categoryParam = category !== "all" ? `?category=${category}` : "";
        const res = await fetch(`${RSS_API}/api/news/cybersecurity${categoryParam}`, {
          signal: AbortSignal.timeout(10000)
        });
        
        if (res.ok) {
          data = await res.json();
          useRss = true;
        } else {
          throw new Error("RSS server not responding");
        }
      } catch (rssErr) {
        console.log("RSS server unavailable, trying Flask backend...");
        const res = await fetch(`${BACKEND_API}/api/cybersecurity-news`);
        if (!res.ok) throw new Error(`Failed to fetch news: ${res.status}`);
        data = await res.json();
      }
      
      if (data.status === 'ok' || data.status === 'success') {
        const processedArticles = data.articles.map((article: any) => ({
          title: article.title || "",
          url: article.url || article.link || "#",
          publishedAt: article.publishedAt || article.published || new Date().toISOString(),
          description: article.description || "",
          source: useRss 
            ? article.source 
            : (typeof article.source === "string" ? article.source : article.source?.name || "News"),
          urlToImage: article.urlToImage || article.image || undefined,
          author: article.author || undefined
        }));
        
        setArticles(processedArticles);
      } else {
        throw new Error(data.message || "Failed to load articles");
      }
    } catch (err: any) {
      console.error(err);
      if (!isAutoRefresh || !articles) {
        setError(err?.message || "Unable to load news. Make sure RSS server is running on port 3001");
      }
    } finally {
      if (!isAutoRefresh) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    fetchNews();
    refreshIntervalRef.current = setInterval(() => {
      fetchNews(true);
    }, AUTO_REFRESH_INTERVAL);

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, [category]);

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

  const getSourceColor = (source: any) => {
    // Handle both string and object source types
    const sourceName = typeof source === "string" ? source : source?.name || "";
    
    const colors: { [key: string]: string } = {
      "Krebs on Security": "bg-blue-100 text-blue-800",
      "BleepingComputer": "bg-purple-100 text-purple-800",
      "The Hacker News": "bg-red-100 text-red-800",
      "Dark Reading": "bg-orange-100 text-orange-800",
      "Security Affairs": "bg-red-100 text-red-800",
      "ZDNet Security": "bg-purple-100 text-purple-800",
      "SANS ISC Diary": "bg-green-100 text-green-800",
    };
    return colors[sourceName] || "bg-gray-100 text-gray-800";
  };

  const getSourceDisplayName = (source: any) => {
    return typeof source === "string" ? source : source?.name || "News";
  };

  const stripHtml = (html: string) => {
    const tmp = document.createElement("div");
    tmp.innerHTML = html;
    return tmp.textContent || tmp.innerText || "";
  };

  const categories = ["all", "general", "analysis", "enterprise", "threats", "government"];

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
              <span className="text-muted-foreground">
                Live RSS feeds from 5 trusted cybersecurity sources - Auto-refreshes every 10 minutes
              </span>
            </div>
            <div className="text-sm font-medium">
              {articles && <span>{articles.length} articles</span>}
            </div>
          </div>
        </div>

        {/* Category Filters */}
        <div className="flex gap-2 flex-wrap">
          {categories.map((cat) => (
            <Button
              key={cat}
              onClick={() => setCategory(cat)}
              variant={category === cat ? "default" : "outline"}
              size="sm"
              className="capitalize"
            >
              {cat === "all" ? "All News" : cat}
            </Button>
          ))}
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
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[1, 2, 3, 4, 5, 6, 7, 8, 9].map((i) => (
              <Card key={i} className="flex flex-col h-full">
                <div className="w-full h-48 bg-muted" />
                <CardHeader className="flex-grow">
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

        {/* Articles List - 3x3 Grid */}
        {!loading && articles && articles.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {articles.map((article, idx) => (
              <Card 
                key={idx} 
                className="hover:shadow-lg transition-shadow border-l-4 border-l-primary flex flex-col h-full"
              >
                {article.urlToImage && (
                  <div className="w-full h-48 overflow-hidden rounded-t-lg">
                    <img 
                      src={article.urlToImage} 
                      alt={article.title}
                      className="w-full h-full object-cover hover:scale-105 transition-transform"
                      onError={(e) => {e.currentTarget.style.display = 'none'}}
                    />
                  </div>
                )}

                <CardHeader className="flex-grow">
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1">
                        <CardTitle className="text-base leading-tight mb-2 line-clamp-2">
                          {article.title}
                        </CardTitle>
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge className={`${getSourceColor(article.source)} font-semibold text-xs`}>
                            {getSourceDisplayName(article.source)}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {formatDate(article.publishedAt)}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="space-y-4 flex-grow">
                  <p className="text-sm text-muted-foreground leading-relaxed line-clamp-3">
                    {stripHtml(article.description)}
                  </p>
                </CardContent>

                <div className="px-6 pb-6 mt-auto">
                  <Button 
                    asChild 
                    variant="default" 
                    size="sm"
                    className="w-full gap-2"
                  >
                    <a 
                      href={article.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                    >
                      Read Full Article
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  </Button>
                </div>
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
            Aggregating the latest cybersecurity news from NewsAPI.
            <br />
            News auto-refreshes in the background.
          </p>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default UnifiedCyberNews;
