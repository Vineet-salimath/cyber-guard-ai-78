"""
Cache Manager for MalwareSnipper
Implements optimized scan result caching with TTL
"""

import sqlite3
import json
from datetime import datetime, timedelta
import hashlib


class ScanCache:
    """Manages scan result caching with TTL (Time To Live)"""
    
    def __init__(self, db_path='malware_scanner.db'):
        """
        Initialize cache manager
        
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_cache_table()
    
    def _init_cache_table(self):
        """Create cache table if it doesn't exist"""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                url_hash TEXT NOT NULL,
                result JSON NOT NULL,
                phase TEXT,
                cached_at INTEGER,
                ttl_hours INTEGER DEFAULT 24
            )
        """)
        
        # Create index for fast lookups
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_cache_url 
            ON scan_cache(url)
        """)
        
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_cache_cached_at 
            ON scan_cache(cached_at DESC)
        """)
        
        self.conn.commit()
    
    def get_cached_scan(self, url, ttl_hours=24):
        """
        Retrieve cached scan if within TTL
        
        Args:
            url: URL to lookup
            ttl_hours: Time-to-live in hours (default 24)
        
        Returns:
            Cached result dict or None if expired/missing
        """
        try:
            cutoff_timestamp = int((datetime.now() - timedelta(hours=ttl_hours)).timestamp())
            
            cursor = self.conn.execute("""
                SELECT result, phase, cached_at FROM scan_cache 
                WHERE url = ? AND cached_at > ?
                ORDER BY cached_at DESC LIMIT 1
            """, (url, cutoff_timestamp))
            
            row = cursor.fetchone()
            if row:
                return {
                    'cached': True,
                    'result': json.loads(row['result']),
                    'phase': row['phase'],
                    'age_seconds': int(datetime.now().timestamp()) - row['cached_at']
                }
            
            return None
            
        except Exception as e:
            print(f"❌ Error retrieving cached scan: {e}")
            return None
    
    def cache_scan(self, url, results, phase, ttl_hours=24):
        """
        Store scan results with phase indicator
        
        Args:
            url: URL scanned
            results: Scan results dict
            phase: Scan phase (instant/fast/deep/complete)
            ttl_hours: Time-to-live in hours (default 24)
        
        Returns:
            True if successful, False otherwise
        """
        try:
            url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
            timestamp = int(datetime.now().timestamp())
            result_json = json.dumps(results)
            
            # Try to update existing entry first
            self.conn.execute("""
                UPDATE scan_cache 
                SET result = ?, phase = ?, cached_at = ?, ttl_hours = ?
                WHERE url = ?
            """, (result_json, phase, timestamp, ttl_hours, url))
            
            # If no rows updated, insert new
            if self.conn.total_changes == 0:
                self.conn.execute("""
                    INSERT INTO scan_cache 
                    (url, url_hash, result, phase, cached_at, ttl_hours)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (url, url_hash, result_json, phase, timestamp, ttl_hours))
            
            self.conn.commit()
            return True
            
        except Exception as e:
            print(f"❌ Error caching scan: {e}")
            return False
    
    def clear_expired_cache(self):
        """Remove all expired cache entries"""
        try:
            now = int(datetime.now().timestamp())
            
            # Delete entries where cached_at + (ttl_hours * 3600) < now
            self.conn.execute("""
                DELETE FROM scan_cache 
                WHERE cached_at + (ttl_hours * 3600) < ?
            """, (now,))
            
            deleted_count = self.conn.total_changes
            self.conn.commit()
            
            print(f"🗑️ Cleared {deleted_count} expired cache entries")
            return deleted_count
            
        except Exception as e:
            print(f"❌ Error clearing expired cache: {e}")
            return 0
    
    def clear_all_cache(self):
        """Clear entire scan cache"""
        try:
            self.conn.execute("DELETE FROM scan_cache")
            self.conn.commit()
            print("🗑️ Cleared all scan cache")
            return True
        except Exception as e:
            print(f"❌ Error clearing cache: {e}")
            return False
    
    def get_cache_stats(self):
        """Get cache statistics"""
        try:
            cursor = self.conn.execute("""
                SELECT 
                    COUNT(*) as total_entries,
                    COUNT(CASE WHEN phase = 'instant' THEN 1 END) as instant_count,
                    COUNT(CASE WHEN phase = 'fast' THEN 1 END) as fast_count,
                    COUNT(CASE WHEN phase = 'deep' THEN 1 END) as deep_count,
                    COUNT(CASE WHEN phase = 'complete' THEN 1 END) as complete_count
                FROM scan_cache
            """)
            
            row = cursor.fetchone()
            return {
                'total_entries': row[0],
                'instant': row[1],
                'fast': row[2],
                'deep': row[3],
                'complete': row[4]
            }
            
        except Exception as e:
            print(f"❌ Error getting cache stats: {e}")
            return {}
    
    def __del__(self):
        """Cleanup: close database connection"""
        try:
            self.conn.close()
        except:
            pass
