"""
Flask API server for Cybersecurity News Aggregator
Provides REST endpoints for fetching and caching news articles
"""
import os
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import logging

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from news_manager import NewsManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize news manager
news_manager = NewsManager()

# ============================================
# Health & Status Endpoints
# ============================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'Cybersecurity News Aggregator'
    }), 200


@app.route('/api/health', methods=['GET'])
def api_health():
    """API health check"""
    return jsonify({
        'status': 'ok',
        'service': 'News API',
        'timestamp': datetime.now().isoformat()
    }), 200


# ============================================
# News Categories Endpoint
# ============================================

@app.route('/api/news/categories', methods=['GET'])
def get_categories():
    """Get available news categories"""
    try:
        categories = news_manager.get_categories()
        return jsonify({
            'success': True,
            'categories': categories,
            'count': len(categories),
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Error getting categories: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


# ============================================
# News Articles Endpoints
# ============================================

@app.route('/api/news/<category>', methods=['GET'])
def get_articles(category):
    """Get articles for a specific category"""
    try:
        force_refresh = request.args.get('refresh', 'false').lower() == 'true'
        limit = request.args.get('limit', 20, type=int)

        result = news_manager.get_articles(category, force_refresh=force_refresh)

        if 'error' in result:
            return jsonify({
                'success': False,
                'error': result['error'],
                'articles': result.get('articles', []),
                'timestamp': datetime.now().isoformat()
            }), 400

        return jsonify({
            'success': True,
            'category': category,
            'articles': result['articles'][:limit],
            'cached': result.get('cached', False),
            'timestamp': result.get('timestamp', datetime.now().isoformat()),
            'age_seconds': result.get('age_seconds', 0),
            'total_articles': len(result.get('articles', []))
        }), 200

    except Exception as e:
        logger.error(f"Error fetching articles for {category}: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


# ============================================
# Refresh Endpoints
# ============================================

@app.route('/api/news/refresh', methods=['POST'])
def refresh_all():
    """Force refresh all categories"""
    try:
        result = news_manager.refresh_all()
        return jsonify({
            'success': True,
            'message': 'All categories refreshed',
            'timestamp': result.get('timestamp'),
            'results': result.get('results', {})
        }), 200
    except Exception as e:
        logger.error(f"Error refreshing articles: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/api/news/refresh/<category>', methods=['POST'])
def refresh_category(category):
    """Refresh specific category"""
    try:
        result = news_manager.get_articles(category, force_refresh=True)

        if 'error' in result and 'Unknown category' in result['error']:
            return jsonify({
                'success': False,
                'error': result['error'],
                'timestamp': datetime.now().isoformat()
            }), 400

        return jsonify({
            'success': True,
            'category': category,
            'articles_count': len(result.get('articles', [])),
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error refreshing {category}: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


# ============================================
# Error Handlers
# ============================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'path': request.path,
        'timestamp': datetime.now().isoformat()
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'timestamp': datetime.now().isoformat()
    }), 500


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors"""
    return jsonify({
        'success': False,
        'error': 'Method not allowed',
        'method': request.method,
        'path': request.path,
        'timestamp': datetime.now().isoformat()
    }), 405


# ============================================
# Server Initialization
# ============================================

if __name__ == '__main__':
    # Get configuration from environment
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    host = os.getenv('HOST', '0.0.0.0')

    logger.info(f"Starting Cybersecurity News Aggregator API")
    logger.info(f"Host: {host}")
    logger.info(f"Port: {port}")
    logger.info(f"Debug: {debug}")
    logger.info(f"Available categories: {', '.join(news_manager.get_categories())}")

    try:
        app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
