const express = require('express');
const Parser = require('rss-parser');
const cors = require('cors');
require('dotenv').config();

const app = express();
const parser = new Parser();

app.use(cors());
app.use(express.json());

// RSS Sources Configuration
const RSS_SOURCES = {
  'krebs-on-security': {
    name: 'Krebs on Security',
    url: 'https://krebsonsecurity.com/feed/',
    category: 'analysis',
    icon: '🔵'
  },
  'bleeping-computer': {
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed/',
    category: 'general',
    icon: '🟠'
  },
  'security-news': {
    name: 'Security Affairs',
    url: 'https://securityaffairs.com/feed',
    category: 'threats',
    icon: '🔴'
  },
  'zeroday-feed': {
    name: 'ZDNet Security',
    url: 'https://www.zdnet.com/topic/security/rss.xml',
    category: 'enterprise',
    icon: '🟣'
  },
  'sans-isc': {
    name: 'SANS ISC Diary',
    url: 'https://isc.sans.edu/rssfeed.xml',
    category: 'analysis',
    icon: '🟢'
  }
};

// Cache implementation
let cache = {
  articles: [],
  timestamp: 0,
  cacheAge: 0
};

const CACHE_DURATION = 10 * 60 * 1000; // 10 minutes
const UPDATE_INTERVAL = 60 * 1000; // Check cache every minute

// Function to fetch and parse RSS feeds
async function fetchAllFeeds() {
  console.log('[RSS] Starting feed aggregation...');
  const articles = [];
  const errors = [];
  
  for (const [key, source] of Object.entries(RSS_SOURCES)) {
    try {
      console.log(`[RSS] Fetching ${source.name}...`);
      const feed = await parser.parseURL(source.url);
      
      feed.items.forEach(item => {
        articles.push({
          title: item.title || 'Untitled',
          description: item.contentSnippet || item.summary || 'No description',
          url: item.link,
          image: item.enclosure?.url || extractImageFromContent(item.content) || null,
          publishedAt: item.pubDate || new Date().toISOString(),
          source: {
            name: source.name,
            category: source.category,
            icon: source.icon
          },
          guid: item.guid || item.link
        });
      });
      
      console.log(`[RSS] ✓ ${source.name}: ${feed.items.length} articles`);
    } catch (error) {
      console.error(`[RSS] ✗ Error fetching ${source.name}: ${error.message}`);
      errors.push(`${source.name}: ${error.message}`);
    }
  }
  
  // Sort by date (newest first)
  articles.sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));
  
  // Remove duplicates
  const uniqueArticles = [];
  const seen = new Set();
  for (const article of articles) {
    if (!seen.has(article.guid)) {
      seen.add(article.guid);
      uniqueArticles.push(article);
    }
  }
  
  console.log(`[RSS] Total unique articles: ${uniqueArticles.length}`);
  if (errors.length > 0) {
    console.log(`[RSS] Errors: ${errors.join(', ')}`);
  }
  
  return uniqueArticles;
}

// Extract image from RSS item content
function extractImageFromContent(content) {
  if (!content) return null;
  const imgMatch = content.match(/<img[^>]+src=["']([^"']+)["']/i);
  return imgMatch ? imgMatch[1] : null;
}

// Update cache periodically
async function updateCache() {
  const now = Date.now();
  
  // Only update if cache is expired or empty
  if (now - cache.timestamp > CACHE_DURATION) {
    const articles = await fetchAllFeeds();
    cache = {
      articles,
      timestamp: now,
      cacheAge: 0,
      cached: false
    };
  } else {
    cache.cacheAge = Math.floor((now - cache.timestamp) / 1000);
    cache.cached = true;
  }
}

// Auto-update cache
setInterval(updateCache, UPDATE_INTERVAL);

// API Routes

// Main news endpoint
app.get('/api/news/cybersecurity', async (req, res) => {
  try {
    // Check if force refresh is requested
    const forceRefresh = req.query.refresh === 'true';
    
    // Update cache if needed or if force refresh is requested
    if (forceRefresh) {
      console.log('[RSS] Force refresh requested - fetching fresh data');
      const articles = await fetchAllFeeds();
      cache = {
        articles,
        timestamp: Date.now(),
        cacheAge: 0,
        cached: false
      };
    } else {
      await updateCache();
    }
    
    const category = req.query.category || 'all';
    let articles = cache.articles;
    
    // Filter by category
    if (category !== 'all') {
      articles = articles.filter(a => a.source.category === category);
    }
    
    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const start = (page - 1) * limit;
    const paginated = articles.slice(start, start + limit);
    
    res.json({
      status: 'ok',
      articles: paginated,
      totalResults: articles.length,
      cached: cache.cached,
      cacheAge: cache.cacheAge,
      sources: Object.values(RSS_SOURCES),
      timestamp: new Date(cache.timestamp).toISOString()
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({
      status: 'error',
      message: error.message,
      articles: []
    });
  }
});

// Sources endpoint
app.get('/api/sources', (req, res) => {
  res.json({
    status: 'ok',
    sources: Object.values(RSS_SOURCES),
    count: Object.keys(RSS_SOURCES).length
  });
});

// Category endpoint
app.get('/api/categories', (req, res) => {
  const categories = [...new Set(Object.values(RSS_SOURCES).map(s => s.category))];
  res.json({
    status: 'ok',
    categories: ['all', ...categories]
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'RSS News Aggregator is running',
    articles: cache.articles.length,
    cacheAge: cache.cacheAge
  });
});

// Initialize cache on startup
async function startup() {
  console.log('🚀 Starting RSS News Aggregator...');
  await updateCache();
  
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`📡 RSS Server running on http://localhost:${PORT}`);
    console.log(`📰 RSS sources configured: ${Object.keys(RSS_SOURCES).length}`);
    console.log(`📊 Initial articles cached: ${cache.articles.length}`);
  });
}

startup();
