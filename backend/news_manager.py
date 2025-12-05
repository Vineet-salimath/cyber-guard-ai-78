"""
CyberNews Module - Real-Time Cybersecurity News System
Integrates with NewsAPI and RSS feeds for live threat intelligence
"""

import requests
import sqlite3
from datetime import datetime, timedelta
import feedparser
from typing import List, Dict, Optional
import json

class CyberNewsManager:
    """Manage real-time cybersecurity news from multiple sources"""
    
    # NewsAPI Configuration
    NEWSAPI_KEY = "273e03fcc564455b994ea18a8f1a4bb7"  # NewsAPI Key
    NEWSAPI_URL = "https://newsapi.org/v2/everything"
    
    # Cybersecurity Keywords
    CYBER_KEYWORDS = [
        'cybersecurity', 'malware', 'ransomware', 'data breach',
        'vulnerability', 'zero-day', 'hacking', 'cyber attack',
        'phishing', 'DDoS', 'exploit', 'CVE', 'security patch',
        'threat', 'APT', 'botnet', 'cryptojacking', 'supply chain attack'
    ]
    
    # RSS Feeds
    RSS_FEEDS = {
        'krebs': 'https://krebsonsecurity.com/feed/',
        'bleeping': 'https://www.bleepingcomputer.com/feed/',
        'hackernews': 'https://thehackernews.com/feeds/posts/default',
        'darkreading': 'https://www.darkreading.com/rss.xml',
        'securityweek': 'https://www.securityweek.com/feed/',
    }
    
    DB_PATH = 'cybernews.db'
    
    def __init__(self):
        """Initialize database"""
        self.init_database()
    
    def init_database(self):
        """Create SQLite database for news caching"""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS news_articles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL UNIQUE,
                    description TEXT,
                    link TEXT UNIQUE,
                    source TEXT,
                    published TEXT,
                    category TEXT,
                    image_url TEXT,
                    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    priority TEXT DEFAULT 'medium'
                )
            ''')
            
            c.execute('''
                CREATE TABLE IF NOT EXISTS news_categories (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE,
                    keyword TEXT,
                    priority TEXT
                )
            ''')
            
            # Insert categories
            categories = [
                ('malware', 'malware|ransomware|trojan|virus|spyware|worm', 'high'),
                ('breach', 'breach|leak|hacked|stolen|compromised|data loss', 'high'),
                ('vulnerability', 'vulnerability|CVE|patch|exploit|zero-day|n-day', 'high'),
                ('threat', 'threat|attack|phishing|DDoS|APT|botnet', 'high'),
                ('supply-chain', 'supply chain|SolarWinds|Kaseya|Okta', 'medium'),
                ('privacy', 'privacy|GDPR|CCPA|data protection', 'medium'),
                ('compliance', 'compliance|regulation|security standard', 'low'),
            ]
            
            for cat_name, keywords, priority in categories:
                c.execute('''
                    INSERT OR IGNORE INTO news_categories (name, keyword, priority)
                    VALUES (?, ?, ?)
                ''', (cat_name, keywords, priority))
            
            conn.commit()
            conn.close()
            print("✅ News database initialized")
            return True
            
        except Exception as e:
            print(f"❌ Database init error: {e}")
            return False
    
    def categorize_article(self, title: str, description: str = "") -> str:
        """Categorize article based on content"""
        content = (title + " " + description).lower()
        
        # Check high priority categories first
        if any(word in content for word in ['malware', 'ransomware', 'trojan', 'virus', 'spyware', 'worm']):
            return 'malware'
        elif any(word in content for word in ['breach', 'leak', 'hacked', 'stolen', 'compromised']):
            return 'breach'
        elif any(word in content for word in ['vulnerability', 'cve', 'patch', 'exploit', 'zero-day']):
            return 'vulnerability'
        elif any(word in content for word in ['ddos', 'attack', 'threat', 'phishing', 'apt']):
            return 'threat'
        elif any(word in content for word in ['supply chain', 'solarwinds', 'kaseya', 'okta']):
            return 'supply-chain'
        else:
            return 'general'
    
    def fetch_from_newsapi(self, limit: int = 30) -> List[Dict]:
        """Fetch news from NewsAPI with STRONG cybersecurity focus"""
        if self.NEWSAPI_KEY == "YOUR_NEWSAPI_KEY_HERE":
            print("⚠️ NewsAPI key not configured, skipping NewsAPI source")
            return []
        
        articles = []
        try:
            # Use STRONG cybersecurity keywords to filter out general news
            # Focus on actual threat terms
            specific_queries = [
                '(malware OR ransomware OR trojan) AND (attack OR threat)',
                '(vulnerability OR CVE OR zero-day OR exploit) AND security',
                '(data breach OR hacked OR compromised) AND (organization OR company)',
                '(phishing OR DDoS OR botnet) AND cybersecurity',
                'ransomware AND (payment OR encrypted OR attack)'
            ]
            
            today = datetime.now().strftime('%Y-%m-%d')
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            
            for search_query in specific_queries:
                params = {
                    'q': search_query,
                    'from': yesterday,
                    'to': today,
                    'sortBy': 'publishedAt',
                    'language': 'en',
                    'pageSize': limit // 5,  # Divide limit across multiple queries
                    'apiKey': self.NEWSAPI_KEY
                }
                
                try:
                    response = requests.get(self.NEWSAPI_URL, params=params, timeout=10)
                    data = response.json()
                    
                    if data.get('status') == 'ok':
                        for article in data.get('articles', []):
                            try:
                                title = article.get('title', '')
                                description = article.get('description', '')
                                
                                # Skip non-cybersecurity articles
                                if not any(kw.lower() in (title + " " + description).lower() 
                                          for kw in self.CYBER_KEYWORDS):
                                    continue
                                
                                category = self.categorize_article(title, description)
                                
                                news_item = {
                                    'title': title,
                                    'description': description[:300],
                                    'link': article.get('url', ''),
                                    'source': article.get('source', {}).get('name', 'NewsAPI'),
                                    'published': article.get('publishedAt', datetime.now().isoformat()),
                                    'category': category,
                                    'image_url': article.get('urlToImage', ''),
                                    'priority': 'high' if category in ['malware', 'breach', 'vulnerability'] else 'medium'
                                }
                                
                                # Avoid duplicates
                                if not any(a['link'] == news_item['link'] for a in articles):
                                    articles.append(news_item)
                                    self.save_to_db(news_item)
                            except Exception as e:
                                print(f"⚠️ Error processing article: {e}")
                                continue
                    else:
                        print(f"⚠️ NewsAPI query failed: {data.get('message', 'Unknown error')}")
                
                except Exception as e:
                    print(f"⚠️ Error fetching from query '{search_query}': {e}")
                    continue
            
            # If we got fewer articles than requested, fetch general cybersecurity news
            if len(articles) < limit:
                params = {
                    'q': 'cybersecurity OR security threat',
                    'from': yesterday,
                    'to': today,
                    'sortBy': 'publishedAt',
                    'language': 'en',
                    'pageSize': limit - len(articles),
                    'apiKey': self.NEWSAPI_KEY
                }
                
                try:
                    response = requests.get(self.NEWSAPI_URL, params=params, timeout=10)
                    data = response.json()
                    
                    if data.get('status') == 'ok':
                        for article in data.get('articles', []):
                            if len(articles) >= limit:
                                break
                            
                            try:
                                category = self.categorize_article(
                                    article.get('title', ''),
                                    article.get('description', '')
                                )
                                
                                news_item = {
                                    'title': article.get('title', 'N/A'),
                                    'description': article.get('description', '')[:300],
                                    'link': article.get('url', ''),
                                    'source': article.get('source', {}).get('name', 'NewsAPI'),
                                    'published': article.get('publishedAt', datetime.now().isoformat()),
                                    'category': category,
                                    'image_url': article.get('urlToImage', ''),
                                    'priority': 'high' if category in ['malware', 'breach'] else 'medium'
                                }
                                
                                if not any(a['link'] == news_item['link'] for a in articles):
                                    articles.append(news_item)
                                    self.save_to_db(news_item)
                            except Exception as e:
                                print(f"⚠️ Error processing article: {e}")
                                continue
                except Exception as e:
                    print(f"⚠️ Fallback query error: {e}")
            
            print(f"✅ Fetched {len(articles)} cybersecurity articles from NewsAPI")
        
        except Exception as e:
            print(f"❌ NewsAPI fetch error: {e}")
        
        return articles
    
    def fetch_from_rss(self, limit: int = 6) -> List[Dict]:
        """Fetch news from RSS feeds"""
        articles = []
        
        for feed_name, feed_url in self.RSS_FEEDS.items():
            try:
                print(f"  📡 Fetching from {feed_name}...")
                feed = feedparser.parse(feed_url)
                
                if not feed.entries:
                    print(f"    ⚠️ No entries from {feed_name}")
                    continue
                
                for entry in feed.entries[:limit]:
                    try:
                        category = self.categorize_article(
                            entry.get('title', ''),
                            entry.get('summary', '')
                        )
                        
                        news_item = {
                            'title': entry.get('title', 'N/A'),
                            'description': entry.get('summary', '')[:300],
                            'link': entry.get('link', ''),
                            'source': feed_name.replace('_', ' ').title(),
                            'published': entry.get('published', datetime.now().isoformat()),
                            'category': category,
                            'image_url': '',
                            'priority': 'high' if category in ['malware', 'breach'] else 'medium'
                        }
                        
                        articles.append(news_item)
                        self.save_to_db(news_item)
                    except Exception as e:
                        continue
                
                print(f"    ✅ Fetched {min(limit, len(feed.entries))} from {feed_name}")
            
            except Exception as e:
                print(f"  ❌ Error fetching from {feed_name}: {e}")
                continue
        
        return articles
    
    def save_to_db(self, article: Dict) -> bool:
        """Save article to database"""
        try:
            conn = sqlite3.connect(self.DB_PATH, timeout=10.0)
            c = conn.cursor()
            c.execute('''
                INSERT OR IGNORE INTO news_articles
                (title, description, link, source, published, category, image_url, priority)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                article['title'],
                article['description'],
                article['link'],
                article['source'],
                article['published'],
                article['category'],
                article.get('image_url', ''),
                article.get('priority', 'medium')
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"⚠️ Database save error: {e}")
            return False
    
    def get_latest_news(self, limit: int = 50) -> List[Dict]:
        """Get latest news from database"""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute('''
                SELECT * FROM news_articles
                ORDER BY fetched_at DESC
                LIMIT ?
            ''', (limit,))
            
            rows = c.fetchall()
            conn.close()
            
            articles = [dict(row) for row in rows]
            return articles
        except Exception as e:
            print(f"❌ Database fetch error: {e}")
            return []
    
    def get_by_category(self, category: str, limit: int = 30) -> List[Dict]:
        """Get news by category"""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute('''
                SELECT * FROM news_articles
                WHERE category = ?
                ORDER BY fetched_at DESC
                LIMIT ?
            ''', (category, limit))
            
            rows = c.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"❌ Database fetch error: {e}")
            return []
    
    def get_stats(self) -> Dict:
        """Get statistics"""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            c = conn.cursor()
            
            c.execute('SELECT COUNT(*) FROM news_articles')
            total = c.fetchone()[0]
            
            c.execute('''
                SELECT category, COUNT(*) as count
                FROM news_articles
                GROUP BY category
            ''')
            
            categories = dict(c.fetchall())
            conn.close()
            
            return {
                'total_articles': total,
                'by_category': categories
            }
        except Exception as e:
            print(f"❌ Stats error: {e}")
            return {'total_articles': 0, 'by_category': {}}
    
    def search_news(self, keyword: str, limit: int = 20) -> List[Dict]:
        """Search news by keyword"""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute('''
                SELECT * FROM news_articles
                WHERE title LIKE ? OR description LIKE ?
                ORDER BY fetched_at DESC
                LIMIT ?
            ''', (f'%{keyword}%', f'%{keyword}%', limit))
            
            rows = c.fetchall()
            conn.close()
            
            return [dict(row) for row in rows]
        except Exception as e:
            print(f"❌ Search error: {e}")
            return []
    
    def cleanup_old_articles(self, days: int = 7) -> int:
        """Remove articles older than N days"""
        try:
            conn = sqlite3.connect(self.DB_PATH)
            c = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            c.execute('DELETE FROM news_articles WHERE fetched_at < ?', (cutoff_date,))
            
            deleted = c.rowcount
            conn.commit()
            conn.close()
            
            print(f"🗑️ Cleaned up {deleted} old articles")
            return deleted
        except Exception as e:
            print(f"❌ Cleanup error: {e}")
            return 0
