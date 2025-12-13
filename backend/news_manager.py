"""
News Manager Service - Fetches and caches cybersecurity news from NewsAPI and RSS feeds
"""
import os
import json
import sqlite3
import requests
import random
import feedparser
from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# NewsAPI configuration
NEWS_API_KEY = os.getenv('NEWS_API_KEY', '')
NEWS_API_BASE_URL = 'https://newsapi.org/v2/everything'

# Database configuration
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'cache.db')
CACHE_TTL = 3600  # 1 hour in seconds

# Premium cybersecurity RSS feeds (15 sources)
PREMIUM_RSS_FEEDS = [
    'https://feeds.bleepingcomputer.com/feed/',  # BleepingComputer
    'https://www.darkreading.com/rss.xml',  # Dark Reading
    'https://feeds.securityweek.com/securityweek/home',  # SecurityWeek
    'https://www.infosecurity-magazine.com/rss.xml',  # Infosecurity Magazine
    'https://feeds.arstechnica.com/arstechnica/security',  # Ars Technica
    'https://www.helpnetsecurity.com/feed/',  # Help Net Security
    'https://feeds.reuters.com/reuters/businessNews',  # Reuters
    'https://feeds.techcrunch.com/techcrunch/',  # TechCrunch
    'https://feeds.wired.com/feed/wired/index.xml',  # Wired
    'https://www.theregister.co.uk/security/headlines.atom',  # The Register
    'https://feeds.zdnet.com/zdnet/security',  # ZDNet
    'https://feeds.thehackernews.com/feed',  # The Hacker News
    'https://krebsonsecurity.com/feed/',  # Krebs on Security
    'https://securityintelligence.com/feed/',  # Security Intelligence
    'https://feeds.fortinet.com/blog/business-and-technology',  # Fortinet
]

# Multiple query variations for each category (20 queries per category)
QUERY_VARIATIONS = {
    'cybersecurity': [
        'cybersecurity',
        'cyber security',
        'cyber attack',
        'cyber threat',
        'cybersecurity news',
        'cyber crime',
        'digital security',
        'information security',
        'IT security',
        'network security',
        'data security',
        'endpoint security',
        'cloud security',
        'application security',
        'security breach',
        'security vulnerability',
        'cyber defense',
        'threat intelligence',
        'incident response',
        'security awareness',
    ],
    'data-breach': [
        'data breach',
        'data breaches',
        'data leak',
        'data leakage',
        'personal data breach',
        'customer data breach',
        'database breach',
        'security breach',
        'information breach',
        'unauthorized access',
        'data compromise',
        'data exposure',
        'stolen data',
        'hacked database',
        'data theft',
        'privacy breach',
        'confidential data leak',
        'sensitive data breach',
        'records stolen',
        'credentials leaked',
    ],
    'ransomware': [
        'ransomware',
        'ransomware attack',
        'ransomware virus',
        'ransomware malware',
        'crypto locker',
        'ransomware gang',
        'ransomware threat',
        'ransomware outbreak',
        'ransomware incident',
        'file encryption attack',
        'extortion malware',
        'ransomware variant',
        'ransomware campaign',
        'ransomware payment',
        'ransomware decryption',
        'wannacry',
        'petya',
        'notpetya',
        'lockbit',
        'conti ransomware',
    ],
    'vulnerability': [
        'vulnerability',
        'CVE',
        'zero day',
        'zero-day',
        'security patch',
        'software vulnerability',
        'security flaw',
        'exploit',
        'bug bounty',
        'vulnerability disclosure',
        'critical vulnerability',
        'security update',
        'unpatched vulnerability',
        'software bug',
        'security hole',
        'remote code execution',
        'SQL injection',
        'cross-site scripting',
        'buffer overflow',
        'privilege escalation',
    ],
    'compliance': [
        'GDPR',
        'CCPA',
        'compliance',
        'regulation',
        'data protection',
        'regulatory',
        'HIPAA',
        'PCI DSS',
        'compliance requirement',
        'regulatory compliance',
        'privacy regulation',
        'data privacy law',
        'privacy policy',
        'compliance audit',
        'compliance violation',
        'data residency',
        'right to be forgotten',
        'data portability',
        'privacy impact assessment',
        'compliance framework',
    ],
    'fraud': [
        'fraud',
        'scam',
        'phishing',
        'phishing attack',
        'email scam',
        'credential theft',
        'identity theft',
        'financial fraud',
        'payment fraud',
        'account takeover',
        'social engineering',
        'spear phishing',
        'whaling',
        'vishing',
        'smishing',
        'ransomware scam',
        'malware scam',
        'fake security alert',
        'romance scam',
        'advance fee fraud',
    ],
    'security-tools': [
        'security tools',
        'antivirus',
        'firewall',
        'VPN',
        'password manager',
        'security software',
        'endpoint protection',
        'intrusion detection',
        'SIEM',
        'vulnerability scanner',
        'penetration testing',
        'security automation',
        'threat detection',
        'security monitoring',
        'SOC tools',
        'identity verification',
        'multi-factor authentication',
        'privileged access management',
        'encryption software',
        'security orchestration',
    ],
    'cloud-security': [
        'cloud security',
        'AWS security',
        'Azure security',
        'Google Cloud security',
        'cloud infrastructure',
        'cloud compliance',
        'cloud data protection',
        'cloud misconfiguration',
        'cloud access control',
        'cloud encryption',
        'cloud security posture',
        'cloud threat',
        'cloud vulnerability',
        'cloud identity',
        'cloud isolation',
        'serverless security',
        'container security',
        'kubernetes security',
        'cloud backup',
        'cloud disaster recovery',
    ],
}

class NewsManager:
    def __init__(self):
        """Initialize news manager and database"""
        self.api_key = NEWS_API_KEY
        if not self.api_key:
            logger.warning("NEWS_API_KEY not set. RSS feeds will be used as primary source.")
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for caching"""
        try:
            os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS news_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    articles TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ttl INTEGER DEFAULT 3600
                )
            ''')
            conn.commit()
            conn.close()
            logger.info(f"Database initialized at {DB_PATH}")
        except Exception as e:
            logger.error(f"Database initialization error: {e}")

    def get_categories(self) -> List[str]:
        """Get list of available categories"""
        return list(QUERY_VARIATIONS.keys())

    def _get_cached_articles(self, category: str) -> Dict[str, Any]:
        """Get articles from cache if still valid"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT articles, timestamp FROM news_cache WHERE category = ? ORDER BY timestamp DESC LIMIT 1',
                (category,)
            )
            result = cursor.fetchone()
            conn.close()

            if result:
                articles_json, timestamp = result
                cached_time = datetime.fromisoformat(timestamp)
                age = (datetime.now() - cached_time).total_seconds()

                if age < CACHE_TTL:
                    articles = json.loads(articles_json)
                    return {
                        'articles': articles,
                        'cached': True,
                        'timestamp': timestamp,
                        'age_seconds': int(age)
                    }
        except Exception as e:
            logger.error(f"Cache retrieval error for {category}: {e}")

        return None

    def _save_to_cache(self, category: str, articles: List[Dict]) -> bool:
        """Save articles to cache"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            articles_json = json.dumps(articles)
            cursor.execute(
                'INSERT INTO news_cache (category, articles, ttl) VALUES (?, ?, ?)',
                (category, articles_json, CACHE_TTL)
            )
            conn.commit()
            conn.close()
            logger.info(f"Saved {len(articles)} articles for {category} to cache")
            return True
        except Exception as e:
            logger.error(f"Cache save error for {category}: {e}")
            return False

    def _fetch_from_newsapi(self, category: str) -> List[Dict[str, Any]]:
        """Fetch articles from NewsAPI with randomized queries"""
        if not self.api_key:
            logger.warning("NewsAPI key not configured, skipping NewsAPI fetch")
            return []

        try:
            # Get random query variation for this category
            queries = QUERY_VARIATIONS.get(category, [category])
            query = random.choice(queries)
            
            params = {
                'q': query,
                'sortBy': 'publishedAt',
                'language': 'en',
                'pageSize': 50,
                'apiKey': self.api_key
            }

            response = requests.get(NEWS_API_BASE_URL, params=params, timeout=10)
            response.raise_for_status()

            data = response.json()
            if data.get('status') != 'ok':
                logger.error(f"NewsAPI error: {data.get('message', 'Unknown error')}")
                return []

            articles = []
            for article in data.get('articles', []):
                processed = {
                    'title': article.get('title', ''),
                    'description': article.get('description', ''),
                    'url': article.get('url', ''),
                    'image': article.get('urlToImage', ''),
                    'source': article.get('source', {}).get('name', 'Unknown'),
                    'publishedAt': article.get('publishedAt', ''),
                    'author': article.get('author', ''),
                    'content': article.get('content', '')
                }
                if processed['title'] and processed['url']:
                    articles.append(processed)

            logger.info(f"Fetched {len(articles)} articles from NewsAPI for '{query}'")
            return articles

        except requests.exceptions.Timeout:
            logger.error(f"Timeout fetching from NewsAPI for {category}")
        except requests.exceptions.RequestException as e:
            logger.error(f"NewsAPI request error for {category}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching from NewsAPI for {category}: {e}")

        return []

    def _fetch_from_rss_feeds(self, category: str) -> List[Dict[str, Any]]:
        """Fetch articles from randomized premium RSS feeds"""
        articles = []
        
        # Randomize feed order for variety
        randomized_feeds = PREMIUM_RSS_FEEDS.copy()
        random.shuffle(randomized_feeds)
        
        for feed_url in randomized_feeds:
            try:
                response = requests.get(feed_url, timeout=5)
                response.raise_for_status()
                
                feed = feedparser.parse(response.content)
                
                for entry in feed.entries[:5]:  # Get 5 articles from each feed
                    # Filter by category keywords
                    title_lower = (entry.get('title', '') or '').lower()
                    description_lower = (entry.get('summary', '') or '').lower()
                    category_keywords = QUERY_VARIATIONS.get(category, [category])
                    
                    # Check if article matches category
                    matches = any(keyword.lower() in title_lower or keyword.lower() in description_lower 
                                 for keyword in category_keywords)
                    
                    if matches:
                        article = {
                            'title': entry.get('title', 'No Title')[:200],
                            'description': entry.get('summary', '')[:500],
                            'url': entry.get('link', ''),
                            'image': entry.get('media_content', [{}])[0].get('url', '') if entry.get('media_content') else '',
                            'source': feed.feed.get('title', 'Unknown Source'),
                            'publishedAt': entry.get('published', datetime.now().isoformat()),
                            'author': entry.get('author', ''),
                            'content': entry.get('content', [{}])[0].get('value', '') if entry.get('content') else ''
                        }
                        if article['title'] and article['url']:
                            articles.append(article)
                            
            except Exception as e:
                logger.debug(f"Error fetching from RSS feed {feed_url}: {e}")
                continue
        
        logger.info(f"Fetched {len(articles)} articles from RSS feeds for {category}")
        return articles

    def get_articles(self, category: str, force_refresh: bool = True) -> Dict[str, Any]:
        """Get articles for a category - ALWAYS FRESH from NewsAPI and RSS feeds"""
        if category not in QUERY_VARIATIONS:
            return {
                'error': f'Unknown category: {category}',
                'articles': [],
                'cached': False,
                'success': False
            }

        # ALWAYS fetch fresh articles (no cache first)
        all_articles = []
        
        # Fetch from NewsAPI
        newsapi_articles = self._fetch_from_newsapi(category)
        all_articles.extend(newsapi_articles)
        
        # Fetch from RSS feeds
        rss_articles = self._fetch_from_rss_feeds(category)
        all_articles.extend(rss_articles)
        
        # Remove duplicates by URL
        seen_urls = set()
        unique_articles = []
        for article in all_articles:
            if article['url'] and article['url'] not in seen_urls:
                seen_urls.add(article['url'])
                unique_articles.append(article)
        
        # Randomize final result for variety on each refresh
        random.shuffle(unique_articles)
        final_articles = unique_articles[:50]  # Return top 50 randomized articles

        # Save to cache for fallback only
        if final_articles:
            self._save_to_cache(category, final_articles)
            return {
                'articles': final_articles,
                'cached': False,
                'timestamp': datetime.now().isoformat(),
                'age_seconds': 0,
                'category': category,
                'success': True,
                'total_articles': len(final_articles),
                'sources': f"NewsAPI ({len(newsapi_articles)}) + RSS ({len(rss_articles)})"
            }
        else:
            # Fallback to cache if fresh fetch fails
            logger.warning(f"Fresh fetch returned no articles for {category}, trying cache fallback")
            cached = self._get_cached_articles(category)
            if cached:
                return {
                    **cached,
                    'error': 'Using cached articles (fresh fetch failed)',
                    'success': True,
                    'category': category
                }
            
            return {
                'articles': [],
                'cached': False,
                'timestamp': datetime.now().isoformat(),
                'age_seconds': 0,
                'category': category,
                'success': True,
                'total_articles': 0,
                'error': 'No articles available'
            }

    def refresh_all(self) -> Dict[str, Any]:
        """Force refresh all categories"""
        results = {}
        for category in self.get_categories():
            try:
                result = self.get_articles(category, force_refresh=True)
                results[category] = {
                    'success': result.get('success', False),
                    'count': result.get('total_articles', 0)
                }
            except Exception as e:
                results[category] = {'success': False, 'error': str(e)}

        return {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'results': results
        }

    def clear_cache(self) -> bool:
        """Clear all cached articles"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM news_cache')
            conn.commit()
            conn.close()
            logger.info("Cache cleared")
            return True
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False

class NewsManager:
    def __init__(self):
        """Initialize news manager and database"""
        self.api_key = NEWS_API_KEY
        if not self.api_key:
            logger.warning("NEWS_API_KEY not set. Some features will be limited.")
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for caching"""
        try:
            os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS news_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    articles TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ttl INTEGER DEFAULT 3600
                )
            ''')
            conn.commit()
            conn.close()
            logger.info(f"Database initialized at {DB_PATH}")
        except Exception as e:
            logger.error(f"Database initialization error: {e}")

    def get_categories(self) -> List[str]:
        """Get list of available categories"""
        return list(CATEGORIES.keys())

    def _get_cached_articles(self, category: str) -> Dict[str, Any]:
        """Get articles from cache if still valid"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT articles, timestamp FROM news_cache WHERE category = ? ORDER BY timestamp DESC LIMIT 1',
                (category,)
            )
            result = cursor.fetchone()
            conn.close()

            if result:
                articles_json, timestamp = result
                cached_time = datetime.fromisoformat(timestamp)
                age = (datetime.now() - cached_time).total_seconds()

                if age < CACHE_TTL:
                    articles = json.loads(articles_json)
                    return {
                        'articles': articles,
                        'cached': True,
                        'timestamp': timestamp,
                        'age_seconds': int(age)
                    }
        except Exception as e:
            logger.error(f"Cache retrieval error for {category}: {e}")

        return None

    def _save_to_cache(self, category: str, articles: List[Dict]) -> bool:
        """Save articles to cache"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            articles_json = json.dumps(articles)
            cursor.execute(
                'INSERT INTO news_cache (category, articles, ttl) VALUES (?, ?, ?)',
                (category, articles_json, CACHE_TTL)
            )
            conn.commit()
            conn.close()
            logger.info(f"Saved {len(articles)} articles for {category} to cache")
            return True
        except Exception as e:
            logger.error(f"Cache save error for {category}: {e}")
            return False

    def _fetch_from_newsapi(self, category: str) -> List[Dict[str, Any]]:
        """Fetch articles from NewsAPI with randomization for variety"""
        if not self.api_key:
            logger.warning("NewsAPI key not configured")
            return []

        try:
            query = CATEGORIES.get(category, category)
            params = {
                'q': query,
                'sortBy': 'publishedAt',
                'language': 'en',
                'pageSize': 20,
                'apiKey': self.api_key
            }

            response = requests.get(NEWS_API_BASE_URL, params=params, timeout=10)
            response.raise_for_status()

            data = response.json()
            if data.get('status') != 'ok':
                logger.error(f"NewsAPI error: {data.get('message', 'Unknown error')}")
                return []

            articles = []
            for article in data.get('articles', [])[:20]:
                processed = {
                    'title': article.get('title', ''),
                    'description': article.get('description', ''),
                    'url': article.get('url', ''),
                    'image': article.get('urlToImage', ''),
                    'source': article.get('source', {}).get('name', 'Unknown'),
                    'publishedAt': article.get('publishedAt', ''),
                    'author': article.get('author', '')
                }
                if processed['title'] and processed['url']:
                    articles.append(processed)

            # Randomize order for variety on each refresh
            random.shuffle(articles)
            
            logger.info(f"Fetched {len(articles)} articles for {category} from NewsAPI (randomized)")
            return articles

        except requests.exceptions.Timeout:
            logger.error(f"Timeout fetching articles for {category}")
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error for {category}: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error for {category}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching articles for {category}: {e}")

        return []

    def get_articles(self, category: str, force_refresh: bool = True) -> Dict[str, Any]:
        """Get articles for a category - always fetches fresh from NewsAPI"""
        if category not in CATEGORIES:
            return {
                'error': f'Unknown category: {category}',
                'articles': [],
                'cached': False
            }

        # Always fetch fresh from API (force_refresh defaults to True)
        articles = self._fetch_from_newsapi(category)

        # Save to cache for fallback
        if articles:
            self._save_to_cache(category, articles)
            return {
                'articles': articles,
                'cached': False,
                'timestamp': datetime.now().isoformat(),
                'age_seconds': 0,
                'category': category,
                'success': True,
                'total_articles': len(articles)
            }
        else:
            # Fallback to cache if fresh fetch fails
            logger.info(f"Fresh fetch failed for {category}, trying cache fallback")
            cached = self._get_cached_articles(category)
            if cached:
                return {
                    **cached,
                    'error': 'Using cached articles (fresh fetch failed)',
                    'success': True
                }
            
            # No cache either - return empty but successful response
            return {
                'articles': [],
                'cached': False,
                'timestamp': datetime.now().isoformat(),
                'age_seconds': 0,
                'category': category,
                'success': True,
                'total_articles': 0
            }

    def refresh_all(self) -> Dict[str, Any]:
        """Force refresh all categories"""
        results = {}
        for category in self.get_categories():
            try:
                articles = self._fetch_from_newsapi(category)
                if articles:
                    self._save_to_cache(category, articles)
                    results[category] = {'success': True, 'count': len(articles)}
                else:
                    results[category] = {'success': False, 'error': 'No articles fetched'}
            except Exception as e:
                results[category] = {'success': False, 'error': str(e)}

        return {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'results': results
        }

    def clear_cache(self) -> bool:
        """Clear all cached articles"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM news_cache')
            conn.commit()
            conn.close()
            logger.info("Cache cleared")
            return True
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False
