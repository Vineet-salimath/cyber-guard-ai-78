// CYBERSECURITY BLOG - Auto-refreshing news feed
import { useState, useEffect } from 'react';
import { ExternalLink, Calendar, Tag, AlertCircle } from 'lucide-react';
import DashboardLayout from '@/components/DashboardLayout';

interface NewsArticle {
  id: string;
  title: string;
  source: string;
  link: string;
  pubDate: string;
  severity: 'high' | 'medium' | 'low';
  category: string;
}

const CyberSecurityBlog = () => {
  const [articles, setArticles] = useState<NewsArticle[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [filter, setFilter] = useState<string>('all');

  useEffect(() => {
    fetchNews();

    // Auto-refresh every 10 seconds (as per spec)
    const interval = setInterval(() => {
      fetchNews();
    }, 10000); // 10 seconds

    return () => clearInterval(interval);
  }, []);

  const fetchNews = async () => {
    try {
      const response = await fetch('http://localhost:5001/api/vulnerability-feed');
      if (response.ok) {
        const data = await response.json();
        setArticles(data);
        setLastUpdate(new Date());
      }
    } catch (error) {
      console.error('Error fetching news:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high':
        return 'bg-red-100 text-red-700 border-red-200';
      case 'medium':
        return 'bg-yellow-100 text-yellow-700 border-yellow-200';
      case 'low':
        return 'bg-blue-100 text-blue-700 border-blue-200';
      default:
        return 'bg-gray-100 text-gray-700 border-gray-200';
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Vulnerability':
        return 'bg-purple-100 text-purple-700';
      case 'Tutorial':
        return 'bg-green-100 text-green-700';
      case 'News':
        return 'bg-blue-100 text-blue-700';
      default:
        return 'bg-gray-100 text-gray-700';
    }
  };

  const filteredArticles = filter === 'all' 
    ? articles 
    : articles.filter(a => a.category.toLowerCase() === filter.toLowerCase());

  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric',
        year: 'numeric'
      });
    } catch {
      return 'Recent';
    }
  };

  return (
    <DashboardLayout>
      <div className="p-6 lg:p-8 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Cybersecurity News</h1>
            <p className="text-muted-foreground">
              Latest vulnerabilities, tutorials, and security news
            </p>
          </div>
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span>Updated {lastUpdate.toLocaleTimeString()}</span>
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="flex gap-2 border-b">
          {['all', 'vulnerability', 'tutorial', 'news'].map((tab) => (
            <button
              key={tab}
              onClick={() => setFilter(tab)}
              className={`px-4 py-2 font-medium capitalize transition border-b-2 ${
                filter === tab
                  ? 'border-primary text-primary'
                  : 'border-transparent text-gray-600 hover:text-gray-900'
              }`}
            >
              {tab}
              <span className="ml-2 text-xs bg-gray-100 px-2 py-1 rounded">
                {tab === 'all' 
                  ? articles.length 
                  : articles.filter(a => a.category.toLowerCase() === tab).length}
              </span>
            </button>
          ))}
        </div>

        {/* Articles Grid */}
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <div className="text-center">
              <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-gray-600">Loading latest news...</p>
            </div>
          </div>
        ) : (
          <div className="grid gap-4">
            {filteredArticles.length === 0 ? (
              <div className="text-center py-20 text-gray-500">
                <AlertCircle className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No articles found in this category.</p>
              </div>
            ) : (
              filteredArticles.map((article) => (
                <a
                  key={article.id}
                  href={article.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block bg-white p-6 rounded-lg border hover:shadow-lg transition group"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getCategoryColor(article.category)}`}>
                          {article.category}
                        </span>
                        <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(article.severity)}`}>
                          {article.severity.toUpperCase()}
                        </span>
                      </div>
                      
                      <h3 className="text-lg font-semibold mb-2 group-hover:text-primary transition">
                        {article.title}
                      </h3>
                      
                      <div className="flex items-center gap-4 text-sm text-gray-600">
                        <div className="flex items-center gap-1">
                          <Tag className="w-4 h-4" />
                          <span>{article.source}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Calendar className="w-4 h-4" />
                          <span>{formatDate(article.pubDate)}</span>
                        </div>
                      </div>
                    </div>
                    
                    <ExternalLink className="w-5 h-5 text-gray-400 group-hover:text-primary transition flex-shrink-0" />
                  </div>
                </a>
              ))
            )}
          </div>
        )}

        {/* Sources Footer */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="text-sm text-blue-900 font-medium mb-2">News Sources</div>
          <div className="flex flex-wrap gap-2 text-xs text-blue-700">
            <span className="bg-white px-3 py-1 rounded">HackerOne</span>
            <span className="bg-white px-3 py-1 rounded">TryHackMe</span>
            <span className="bg-white px-3 py-1 rounded">Threatpost</span>
            <span className="bg-white px-3 py-1 rounded">The Hacker News</span>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default CyberSecurityBlog;
