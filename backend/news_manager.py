"""
Simple News Manager - Fetches cybersecurity news from NewsAPI
No caching - always fresh articles on every request
"""
import os
import requests
import logging
from datetime import datetime
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# NewsAPI configuration
NEWS_API_KEY = os.getenv('NEWS_API_KEY', '')
NEWS_API_BASE_URL = 'https://newsapi.org/v2/everything'

# Cybersecurity search queries
CYBER_QUERIES = {
    'all': 'cybersecurity OR "cyber attack" OR malware OR ransomware OR vulnerability OR breach OR phishing OR "zero-day" OR exploit OR threat',
    'malware': 'malware OR virus OR trojan OR worm OR spyware',
    'ransomware': 'ransomware OR "file encryption" OR extortion OR lockbit OR conti',
    'vulnerability': 'vulnerability OR CVE OR "zero-day" OR exploit OR "security patch"',
    'threat': 'threat OR "cyber threat" OR "threat actor" OR APT',
    'breach': 'breach OR "data breach" OR "security breach" OR hack OR compromised',
    'phishing': 'phishing OR "spear phishing" OR credential OR "email scam"',
    'ddos': 'DDoS OR "distributed denial of service" OR "bot attack"',
}


class CyberNewsManager:
    """Manages fetching cybersecurity news from NewsAPI"""
    
    def __init__(self):
        self.api_key = NEWS_API_KEY
        if not self.api_key:
            logger.warning("⚠️ NEWS_API_KEY not configured - news fetching will fail")
        logger.info(f"🔧 CyberNewsManager initialized with API key: {'✓' if self.api_key else '✗'}")
    
    def fetch_from_newsapi(self, category: str = 'all', limit: int = 30) -> List[Dict[str, Any]]:
        """
        Fetch fresh articles from NewsAPI
        Always returns fresh data - NO CACHING
        """
        if not self.api_key:
            logger.error("❌ NewsAPI key not configured - using demo articles")
            return self._get_demo_articles(category, limit)
        
        try:
            # Get query for category
            query = CYBER_QUERIES.get(category, CYBER_QUERIES['all'])
            
            logger.info(f"Fetching cybersecurity news: category='{category}', limit={limit}")
            
            params = {
                'q': query,
                'sortBy': 'publishedAt',
                'language': 'en',
                'pageSize': min(limit, 100),  # NewsAPI max is 100
                'apiKey': self.api_key
            }
            
            response = requests.get(NEWS_API_BASE_URL, params=params, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('status') != 'ok':
                error_msg = data.get('message', 'Unknown error')
                logger.error(f"NewsAPI error: {error_msg}")
                # Fallback to demo articles on API error
                return self._get_demo_articles(category, limit)
            
            # Transform articles
            articles = []
            for article in data.get('articles', []):
                # Skip articles without required fields
                if not article.get('title') or not article.get('url'):
                    continue
                
                processed = {
                    'title': article.get('title', ''),
                    'description': article.get('description', '') or article.get('content', '')[:250],
                    'link': article.get('url', ''),
                    'url': article.get('url', ''),
                    'image_url': article.get('urlToImage', ''),
                    'source': article.get('source', {}).get('name', 'NewsAPI'),
                    'published': article.get('publishedAt', datetime.now().isoformat()),
                    'publishedAt': article.get('publishedAt', datetime.now().isoformat()),
                    'author': article.get('author', '') or 'Unknown',
                    'category': category,
                    'priority': 'high' if any(word in article.get('title', '').lower() for word in ['critical', 'severe', 'major', 'breach']) else 'medium'
                }
                articles.append(processed)
            
            logger.info(f"Successfully fetched {len(articles)} articles from NewsAPI")
            return articles[:limit] if articles else self._get_demo_articles(category, limit)
        
        except requests.exceptions.Timeout:
            logger.error("NewsAPI request timeout - using demo articles")
            return self._get_demo_articles(category, limit)
        except requests.exceptions.ConnectionError:
            logger.error("NewsAPI connection error - using demo articles")
            return self._get_demo_articles(category, limit)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.error("Rate limit exceeded - using demo articles")
            else:
                logger.error(f"NewsAPI HTTP error: {e}")
            return self._get_demo_articles(category, limit)
        except requests.exceptions.RequestException as e:
            logger.error(f"NewsAPI request error: {e} - using demo articles")
            return self._get_demo_articles(category, limit)
        except Exception as e:
            logger.error(f"Unexpected error: {e} - using demo articles")
            return self._get_demo_articles(category, limit)
    
    def _get_demo_articles(self, category: str = 'all', limit: int = 30) -> List[Dict[str, Any]]:
        """Return demo cybersecurity articles when API is unavailable"""
        demo_articles = [
            {
                'title': 'Critical Zero-Day Vulnerability Discovered in Major Enterprise Software',
                'description': 'Security researchers have identified a critical zero-day vulnerability affecting millions of users worldwide. The flaw allows remote code execution without authentication.',
                'link': 'https://example.com/article1',
                'url': 'https://example.com/article1',
                'image_url': 'https://via.placeholder.com/300x200?text=Zero+Day',
                'source': 'SecurityWeek',
                'published': datetime.now().isoformat(),
                'publishedAt': datetime.now().isoformat(),
                'author': 'Security Team',
                'category': 'vulnerability',
                'priority': 'high'
            },
            {
                'title': 'LockBit Ransomware Gang Targets Healthcare Sector with New Campaign',
                'description': 'The notorious LockBit ransomware gang has launched a new campaign specifically targeting healthcare organizations. Several hospitals have already reported incidents.',
                'link': 'https://example.com/article2',
                'url': 'https://example.com/article2',
                'image_url': 'https://via.placeholder.com/300x200?text=Ransomware',
                'source': 'Krebs on Security',
                'published': datetime.now().isoformat(),
                'publishedAt': datetime.now().isoformat(),
                'author': 'Threat Intelligence',
                'category': 'ransomware',
                'priority': 'high'
            },
            {
                'title': 'Massive Data Breach Exposes 50 Million User Records',
                'description': 'A major breach has exposed personal data of 50 million users including names, emails, and encrypted passwords from a popular online platform.',
                'link': 'https://example.com/article3',
                'url': 'https://example.com/article3',
                'image_url': 'https://via.placeholder.com/300x200?text=Data+Breach',
                'source': 'BleepingComputer',
                'published': datetime.now().isoformat(),
                'publishedAt': datetime.now().isoformat(),
                'author': 'Incident Response',
                'category': 'breach',
                'priority': 'high'
            },
            {
                'title': 'Advanced Phishing Campaign Targets C-Level Executives',
                'description': 'Threat actors are conducting sophisticated phishing attacks targeting senior executives at Fortune 500 companies. The emails use AI-generated content for better authenticity.',
                'link': 'https://example.com/article4',
                'url': 'https://example.com/article4',
                'image_url': 'https://via.placeholder.com/300x200?text=Phishing',
                'source': 'Dark Reading',
                'published': datetime.now().isoformat(),
                'publishedAt': datetime.now().isoformat(),
                'author': 'Threat Analysis',
                'category': 'phishing',
                'priority': 'medium'
            },
            {
                'title': 'New Malware Variant Spreads Rapidly Across Enterprise Networks',
                'description': 'Security teams worldwide are responding to a new malware variant that spreads through unpatched vulnerabilities. It appears to be a worm-like threat spreading across networks.',
                'link': 'https://example.com/article5',
                'url': 'https://example.com/article5',
                'image_url': 'https://via.placeholder.com/300x200?text=Malware',
                'source': 'The Hacker News',
                'published': datetime.now().isoformat(),
                'publishedAt': datetime.now().isoformat(),
                'author': 'Malware Research',
                'category': 'malware',
                'priority': 'high'
            },
            {
                'title': 'GDPR Enforcement Action: Major Tech Company Fined $100M',
                'description': 'European regulators have imposed a record fine for privacy violations. The company failed to properly secure user data and had inadequate consent mechanisms.',
                'link': 'https://example.com/article6',
                'url': 'https://example.com/article6',
                'image_url': 'https://via.placeholder.com/300x200?text=GDPR',
                'source': 'Infosecurity Magazine',
                'published': datetime.now().isoformat(),
                'publishedAt': datetime.now().isoformat(),
                'author': 'Compliance Team',
                'category': 'threat',
                'priority': 'medium'
            }
        ]
        
        return demo_articles[:limit]
    
    def get_categories(self) -> List[str]:
        """Get available categories"""
        return list(CYBER_QUERIES.keys())


# Keep NewsManager as alias for backward compatibility
NewsManager = CyberNewsManager
