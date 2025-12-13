import { useState, useEffect } from 'react';
import { Moon, Sun, RefreshCw, ExternalLink } from 'lucide-react';
import DashboardLayout from '@/components/DashboardLayout';

type Article = {
  title: string;
  description: string;
  url: string;
  image: string;
  source: string;
  publishedAt: string;
  author: string;
};

type CategoryCount = {
  [key: string]: number;
};

const Blog = () => {
  const [articles, setArticles] = useState<Article[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeCategory, setActiveCategory] = useState('cybersecurity');
  const [categories, setCategories] = useState<string[]>([]);
  const [darkMode, setDarkMode] = useState(false);
  const [refreshCountdown, setRefreshCountdown] = useState(300); // 5 minutes
  const [isRefreshing, setIsRefreshing] = useState(false);

  const API_BASE = 'http://localhost:5000/api';

  const CATEGORY_LABELS: CategoryCount = {
    'cybersecurity': 'Cybersecurity',
    'data-breach': 'Data Breach',
    'ransomware': 'Ransomware',
    'vulnerability': 'Vulnerability',
    'compliance': 'Compliance',
    'fraud': 'Fraud',
    'security-tools': 'Security Tools',
    'cloud-security': 'Cloud Security'
  };

  // Load dark mode preference
  useEffect(() => {
    const isDark = localStorage.getItem('darkMode') === 'true';
    setDarkMode(isDark);
  }, []);

  // Toggle dark mode
  const toggleDarkMode = () => {
    const newDarkMode = !darkMode;
    setDarkMode(newDarkMode);
    localStorage.setItem('darkMode', String(newDarkMode));
  };

  // Fetch categories on mount
  useEffect(() => {
    fetchCategories();
  }, []);

  // Fetch articles when category changes
  useEffect(() => {
    fetchArticles(activeCategory);
  }, [activeCategory]);

  // Auto-refresh countdown
  useEffect(() => {
    if (refreshCountdown <= 0) {
      fetchArticles(activeCategory);
      setRefreshCountdown(300);
      return;
    }

    const timer = setTimeout(() => {
      setRefreshCountdown(refreshCountdown - 1);
    }, 1000);

    return () => clearTimeout(timer);
  }, [refreshCountdown, activeCategory]);

  const fetchCategories = async () => {
    try {
      const response = await fetch(`${API_BASE}/news/categories`);
      const data = await response.json();
      if (data.success) {
        setCategories(data.categories);
      }
    } catch (err) {
      console.error('Failed to fetch categories:', err);
    }
  };

  const fetchArticles = async (category: string, forceRefresh = true) => {
    setLoading(true);
    setError(null);

    try {
      // Always request fresh data from NewsAPI and RSS feeds
      // Add timestamp parameter to bypass browser cache
      const timestamp = new Date().getTime();
      const url = `${API_BASE}/news/${category}?refresh=true&t=${timestamp}`;
      const response = await fetch(url);
      const data = await response.json();

      if (data.success) {
        setArticles(data.articles || []);
        if (data.articles && data.articles.length > 0) {
          console.log(`[OK] Loaded ${data.articles.length} fresh articles for ${category} (${data.sources || 'Unknown sources'})`);
        } else {
          setError('No articles found. Try selecting a different category or checking your connection.');
        }
      } else {
        setError(data.error || 'Failed to load articles');
        setArticles([]);
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to fetch articles';
      setError(`Error: ${errorMsg}. Make sure backend is running on port 5000.`);
      setArticles([]);
    } finally {
      setLoading(false);
    }
  };

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await fetchArticles(activeCategory, true);
    setRefreshCountdown(300);
    setIsRefreshing(false);
  };

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric'
      });
    } catch {
      return dateString;
    }
  };

  const formatCountdown = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const contentClass = darkMode ? 'dark bg-gray-900 text-white' : 'bg-gray-50 text-gray-900';
  const headerClass = darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const cardClass = darkMode ? 'bg-gray-800' : 'bg-white';
  const textMutedClass = darkMode ? 'text-gray-400' : 'text-gray-600';
  const buttonHoverClass = darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100';

  return (
    <DashboardLayout>
      <div className={`min-h-screen ${contentClass}`}>
        {/* Header */}
        <div className={`border-b ${headerClass}`}>
          <div className="p-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h1 className="text-3xl font-bold">Cybersecurity News</h1>
                <p className={`text-sm ${textMutedClass}`}>
                  Latest news from the cybersecurity world
                </p>
              </div>

              {/* Header Controls */}
              <div className="flex items-center gap-4">
                {/* Countdown Timer */}
                <div className={`px-4 py-2 rounded-lg ${darkMode ? 'bg-gray-700' : 'bg-gray-100'}`}>
                  <p className={`text-xs ${textMutedClass}`}>
                    Auto-refresh in
                  </p>
                  <p className="font-mono font-bold">{formatCountdown(refreshCountdown)}</p>
                </div>

                {/* Refresh Button */}
                <button
                  onClick={handleManualRefresh}
                  disabled={isRefreshing || loading}
                  className={`p-2 rounded-lg transition-colors ${buttonHoverClass} disabled:opacity-50`}
                  title="Manually refresh articles"
                >
                  <RefreshCw
                    size={20}
                    className={isRefreshing ? 'animate-spin' : ''}
                  />
                </button>

                {/* Dark Mode Toggle */}
                <button
                  onClick={toggleDarkMode}
                  className={`p-2 rounded-lg transition-colors ${buttonHoverClass}`}
                  title="Toggle dark mode"
                >
                  {darkMode ? <Sun size={20} /> : <Moon size={20} />}
                </button>
              </div>
            </div>

            {/* Category Filters */}
            <div className="flex flex-wrap gap-2">
              {categories.length > 0 ? (
                categories.map((category) => (
                  <button
                    key={category}
                    onClick={() => setActiveCategory(category)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                      activeCategory === category
                        ? 'bg-blue-600 text-white'
                        : darkMode
                        ? 'bg-gray-700 hover:bg-gray-600'
                        : 'bg-gray-200 hover:bg-gray-300'
                    }`}
                  >
                    {CATEGORY_LABELS[category] || category}
                  </button>
                ))
              ) : (
                <p className={`text-sm ${textMutedClass}`}>
                  Loading categories...
                </p>
              )}
            </div>
          </div>
        </div>

        {/* Main Content */}
        <main className="p-6">
          {/* Error Message */}
          {error && (
            <div className={`mb-6 p-4 rounded-lg ${
              darkMode
                ? 'bg-red-900 text-red-100'
                : 'bg-red-50 text-red-700'
            }`}>
              <p className="font-semibold">Error loading articles</p>
              <p className="text-sm mt-1">{error}</p>
            </div>
          )}

          {/* Loading State */}
          {loading && articles.length === 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[1, 2, 3, 4, 5, 6].map((i) => (
                <div
                  key={i}
                  className={`rounded-lg p-4 ${cardClass}`}
                >
                  <div className={`h-48 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'} mb-4`}></div>
                  <div className={`h-4 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'} mb-2`}></div>
                  <div className={`h-4 rounded ${darkMode ? 'bg-gray-700' : 'bg-gray-200'} w-3/4`}></div>
                </div>
              ))}
            </div>
          ) : articles.length > 0 ? (
            /* Articles Grid */
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {articles.map((article, index) => (
                <article
                  key={index}
                  className={`rounded-lg overflow-hidden shadow-md hover:shadow-lg transition-shadow ${cardClass}`}
                >
                  {/* Article Image */}
                  {article.image && (
                    <img
                      src={article.image}
                      alt={article.title}
                      className="w-full h-48 object-cover"
                      onError={(e) => {
                        (e.target as HTMLImageElement).style.display = 'none';
                      }}
                    />
                  )}

                  {/* Article Content */}
                  <div className="p-4">
                    {/* Source Badge */}
                    <div className="mb-2">
                      <span className={`inline-block px-2 py-1 text-xs rounded ${
                        darkMode
                          ? 'bg-blue-900 text-blue-300'
                          : 'bg-blue-100 text-blue-800'
                      }`}>
                        {article.source}
                      </span>
                    </div>

                    {/* Title */}
                    <h3 className="font-bold text-lg mb-2 line-clamp-2">
                      {article.title}
                    </h3>

                    {/* Description */}
                    <p className={`text-sm mb-4 line-clamp-3 ${textMutedClass}`}>
                      {article.description || 'No description available'}
                    </p>

                    {/* Metadata */}
                    <div className={`text-xs mb-4 ${textMutedClass}`}>
                      <p>📅 {formatDate(article.publishedAt)}</p>
                      {article.author && <p>✍️ {article.author}</p>}
                    </div>

                    {/* Read More Button */}
                    <a
                      href={article.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
                        darkMode
                          ? 'bg-blue-600 hover:bg-blue-700 text-white'
                          : 'bg-blue-600 hover:bg-blue-700 text-white'
                      }`}
                    >
                      Read More
                      <ExternalLink size={16} />
                    </a>
                  </div>
                </article>
              ))}
            </div>
          ) : (
            /* No Articles */
            <div className={`text-center py-12 rounded-lg ${
              darkMode ? 'bg-gray-800' : 'bg-gray-100'
            }`}>
              <p className={`text-lg font-medium ${
                darkMode ? 'text-gray-300' : 'text-gray-700'
              }`}>
                No articles available
              </p>
              <p className={`text-sm mt-2 ${textMutedClass}`}>
                Try refreshing or selecting a different category
              </p>
            </div>
          )}
        </main>
      </div>
    </DashboardLayout>
  );
};

export default Blog;
