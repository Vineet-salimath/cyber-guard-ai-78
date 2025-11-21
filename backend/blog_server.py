# MALWARE SNIPPER - BLOG FEED SERVER
# Aggregates cybersecurity news from multiple sources

from flask import Flask, jsonify
from flask_cors import CORS
import requests
from datetime import datetime
import xml.etree.ElementTree as ET

app = Flask(__name__)
CORS(app)

# News sources
NEWS_SOURCES = {
    'hackerone': 'https://hackerone.com/blog.rss',
    'tryhackme': 'https://blog.tryhackme.com/rss/',
    'threatpost': 'https://threatpost.com/feed/',
    'thehackernews': 'https://feeds.feedburner.com/TheHackersNews'
}

@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'service': 'Malware Snipper Blog Feed',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/vulnerability-feed', methods=['GET'])
def get_vulnerability_feed():
    """
    Get aggregated cybersecurity news from multiple sources
    
    Response:
    [
        {
            "id": "hackerone-123",
            "title": "New Critical Vulnerability Found",
            "source": "HackerOne",
            "link": "https://...",
            "pubDate": "2025-11-05T12:00:00Z",
            "severity": "high|medium|low",
            "category": "Vulnerability|News|Tutorial"
        }
    ]
    """
    try:
        all_articles = []
        
        # Fetch from HackerOne
        hackerone_articles = fetch_hackerone_news()
        all_articles.extend(hackerone_articles)
        
        # Fetch from TryHackMe
        tryhackme_articles = fetch_tryhackme_news()
        all_articles.extend(tryhackme_articles)
        
        # Fetch from Threatpost
        threatpost_articles = fetch_threatpost_news()
        all_articles.extend(threatpost_articles)
        
        # Fetch from The Hacker News
        thehackernews_articles = fetch_thehackernews()
        all_articles.extend(thehackernews_articles)
        
        # Sort by date (newest first)
        all_articles.sort(key=lambda x: x.get('pubDate', ''), reverse=True)
        
        # Return top 50 articles
        return jsonify(all_articles[:50])
        
    except Exception as e:
        print(f"❌ Error fetching news: {str(e)}")
        return jsonify([]), 500

def fetch_hackerone_news():
    """Fetch news from HackerOne blog"""
    try:
        response = requests.get(NEWS_SOURCES['hackerone'], timeout=5)
        if response.status_code == 200:
            return parse_rss_feed(response.text, 'HackerOne', 'Vulnerability')
    except Exception as e:
        print(f"⚠️ Error fetching HackerOne: {str(e)}")
    
    return generate_mock_articles('HackerOne', 5)

def fetch_tryhackme_news():
    """Fetch news from TryHackMe blog"""
    try:
        response = requests.get(NEWS_SOURCES['tryhackme'], timeout=5)
        if response.status_code == 200:
            return parse_rss_feed(response.text, 'TryHackMe', 'Tutorial')
    except Exception as e:
        print(f"⚠️ Error fetching TryHackMe: {str(e)}")
    
    return generate_mock_articles('TryHackMe', 5)

def fetch_threatpost_news():
    """Fetch news from Threatpost"""
    try:
        response = requests.get(NEWS_SOURCES['threatpost'], timeout=5)
        if response.status_code == 200:
            return parse_rss_feed(response.text, 'Threatpost', 'News')
    except Exception as e:
        print(f"⚠️ Error fetching Threatpost: {str(e)}")
    
    return generate_mock_articles('Threatpost', 5)

def fetch_thehackernews():
    """Fetch news from The Hacker News"""
    try:
        response = requests.get(NEWS_SOURCES['thehackernews'], timeout=5)
        if response.status_code == 200:
            return parse_rss_feed(response.text, 'The Hacker News', 'News')
    except Exception as e:
        print(f"⚠️ Error fetching The Hacker News: {str(e)}")
    
    return generate_mock_articles('The Hacker News', 5)

def parse_rss_feed(xml_content, source, category):
    """Parse RSS feed XML"""
    articles = []
    
    try:
        root = ET.fromstring(xml_content)
        
        # Find all items in the feed
        items = root.findall('.//item')
        
        for item in items[:10]:  # Limit to 10 items per source
            title_elem = item.find('title')
            link_elem = item.find('link')
            pub_date_elem = item.find('pubDate')
            
            if title_elem is not None and link_elem is not None:
                title = title_elem.text or 'No title'
                link = link_elem.text or '#'
                pub_date = pub_date_elem.text if pub_date_elem is not None else datetime.now().isoformat()
                
                # Determine severity based on keywords
                severity = 'medium'
                title_lower = title.lower()
                if any(word in title_lower for word in ['critical', 'zero-day', 'severe', 'dangerous']):
                    severity = 'high'
                elif any(word in title_lower for word in ['minor', 'low', 'patched']):
                    severity = 'low'
                
                articles.append({
                    'id': f"{source.lower().replace(' ', '-')}-{hash(link)}",
                    'title': title,
                    'source': source,
                    'link': link,
                    'pubDate': pub_date,
                    'severity': severity,
                    'category': category
                })
    
    except Exception as e:
        print(f"❌ Error parsing RSS: {str(e)}")
    
    return articles

def generate_mock_articles(source, count):
    """Generate mock articles for testing"""
    mock_titles = {
        'HackerOne': [
            'Critical RCE Vulnerability Discovered in Popular Framework',
            'New Bug Bounty Program: $50,000 for Critical Findings',
            'Authentication Bypass Vulnerability Patched',
            'SQL Injection Vulnerability Found in E-commerce Platform',
            'Zero-Day Exploit Disclosed for Enterprise Software'
        ],
        'TryHackMe': [
            'Learn Buffer Overflow Exploitation - New Tutorial',
            'Advanced Web Application Security Testing',
            'Introduction to Malware Analysis Course',
            'Penetration Testing Fundamentals - Free Room',
            'OWASP Top 10 Vulnerabilities Explained'
        ],
        'Threatpost': [
            'Ransomware Attack Targets Healthcare Sector',
            'New Phishing Campaign Exploits COVID-19 Fears',
            'Critical Windows Vulnerability Under Active Exploitation',
            'Data Breach Exposes Millions of User Credentials',
            'APT Group Launches Sophisticated Supply Chain Attack'
        ],
        'The Hacker News': [
            'Google Patches 5 Critical Android Vulnerabilities',
            'New Cryptocurrency Mining Malware Spreads Rapidly',
            'Microsoft Issues Emergency Patch for Zero-Day Flaw',
            'Russian Hackers Linked to Recent Cyber Espionage Campaign',
            'Security Researchers Discover Major Cloud Platform Bug'
        ]
    }
    
    articles = []
    titles = mock_titles.get(source, ['Mock Article Title'])
    
    for i in range(min(count, len(titles))):
        severity = ['high', 'medium', 'low'][i % 3]
        category = 'Vulnerability' if source == 'HackerOne' else 'Tutorial' if source == 'TryHackMe' else 'News'
        
        articles.append({
            'id': f"{source.lower().replace(' ', '-')}-mock-{i}",
            'title': titles[i],
            'source': source,
            'link': f"https://example.com/{source.lower()}/article-{i}",
            'pubDate': datetime.now().isoformat(),
            'severity': severity,
            'category': category
        })
    
    return articles

if __name__ == '__main__':
    print("📰 MALWARE SNIPPER - Blog Feed Server")
    print(f"📡 Server starting on http://localhost:5001")
    print("="*50)
    
    app.run(host='0.0.0.0', port=5001, debug=True)
