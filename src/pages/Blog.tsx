import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { ExternalLink, RefreshCw, Rss } from "lucide-react";

type BlogPost = {
  title: string;
  link: string;
  pubDate?: string;
  author?: string;
  description?: string;
  thumbnail?: string;
};

const DEFAULT_RSS = "https://threatpost.com/feed/";

const Blog = () => {
  const [posts, setPosts] = useState<BlogPost[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Allow the RSS url to be configured with Vite env var VITE_BLOG_RSS_URL
  const RSS_URL = (import.meta as any).env?.VITE_BLOG_RSS_URL || DEFAULT_RSS;

  const fetchPosts = async () => {
    setLoading(true);
    setError(null);
    try {
      // Use rss2json public endpoint to convert RSS -> JSON
      const api = `https://api.rss2json.com/v1/api.json?rss_url=${encodeURIComponent(RSS_URL)}`;
      const res = await fetch(api);
      if (!res.ok) throw new Error(`Failed to fetch feed: ${res.status}`);
      const json = await res.json();
      const feedItems: BlogPost[] = (json.items || []).map((it: any) => ({
        title: it.title,
        link: it.link,
        pubDate: it.pubDate,
        author: it.author,
        description: it.description,
        thumbnail: it.thumbnail,
      }));
      setPosts(feedItems);
    } catch (err: any) {
      console.error(err);
      setError(err?.message || "Unable to load feed");
      setPosts(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPosts();
  }, []);

  const stripHtml = (html: string) => {
    const tmp = document.createElement("div");
    tmp.innerHTML = html;
    return tmp.textContent || tmp.innerText || "";
  };

  return (
    <DashboardLayout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
              <Rss className="w-8 h-8 text-primary" />
              Cybersecurity Blogs
            </h1>
            <p className="text-muted-foreground mt-2">
              Latest news and insights from the cybersecurity community
            </p>
          </div>
          <Button onClick={fetchPosts} disabled={loading} variant="outline" size="sm">
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>

        {/* Error State */}
        {error && (
          <Card className="border-destructive">
            <CardContent className="pt-6">
              <div className="text-center text-destructive">
                <p className="font-semibold">Failed to load blogs</p>
                <p className="text-sm mt-1">{error}</p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Loading State */}
        {loading && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[1, 2, 3, 4, 5, 6].map((i) => (
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

        {/* Blog Posts Grid */}
        {!loading && !error && posts && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {posts.map((post, idx) => (
              <Card key={idx} className="flex flex-col hover:shadow-lg transition-shadow">
                <CardHeader>
                  <CardTitle className="text-lg line-clamp-2">{post.title}</CardTitle>
                  <CardDescription>
                    {post.pubDate && (
                      <span className="text-xs">
                        {new Date(post.pubDate).toLocaleDateString("en-US", {
                          year: "numeric",
                          month: "short",
                          day: "numeric",
                        })}
                      </span>
                    )}
                    {post.author && (
                      <Badge variant="outline" className="ml-2 text-xs">
                        {post.author}
                      </Badge>
                    )}
                  </CardDescription>
                </CardHeader>

                <CardContent className="flex-1">
                  <p className="text-sm text-muted-foreground line-clamp-4">
                    {post.description ? stripHtml(post.description) : "No description available"}
                  </p>
                </CardContent>

                <CardFooter>
                  <Button asChild variant="outline" size="sm" className="w-full">
                    <a href={post.link} target="_blank" rel="noopener noreferrer">
                      Read More
                      <ExternalLink className="w-4 h-4 ml-2" />
                    </a>
                  </Button>
                </CardFooter>
              </Card>
            ))}
          </div>
        )}

        {/* Empty State */}
        {!loading && !error && posts && posts.length === 0 && (
          <Card>
            <CardContent className="pt-6">
              <div className="text-center text-muted-foreground">
                <p className="font-semibold">No blog posts found</p>
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
