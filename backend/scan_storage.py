# MALWARE SNIPPER - PERSISTENT SCAN STORAGE
# JSON-based storage for scan statistics and history

import json
import os
from datetime import datetime
from threading import Lock

class ScanStorage:
    """Thread-safe persistent storage for scan statistics"""
    
    def __init__(self, storage_path='data/scan_stats.json'):
        self.storage_path = storage_path
        self.lock = Lock()
        self._ensure_data_directory()
        self.stats = self._load_stats()
    
    def _ensure_data_directory(self):
        """Create data directory if it doesn't exist"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
    
    def _load_stats(self):
        """Load statistics from JSON file"""
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            else:
                return self._get_default_stats()
        except Exception as e:
            print(f"⚠️ Error loading stats: {e}")
            return self._get_default_stats()
    
    def _get_default_stats(self):
        """Return default statistics structure"""
        return {
            'total_scans': 0,
            'benign_count': 0,
            'suspicious_count': 0,
            'malicious_count': 0,
            'last_updated': datetime.now().isoformat(),
            'scan_history': []
        }
    
    def _save_stats(self):
        """Save statistics to JSON file"""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self.stats, f, indent=2)
        except Exception as e:
            print(f"❌ Error saving stats: {e}")
    
    def increment_scan(self, url, risk_category, risk_score, ml_prediction=None):
        """
        Increment scan counters and add to history
        
        Args:
            url: The scanned URL
            risk_category: 'benign', 'suspicious', or 'malicious'
            risk_score: Risk score 0-100
            ml_prediction: ML model prediction label
        """
        with self.lock:
            # Increment counters
            self.stats['total_scans'] += 1
            
            if risk_category == 'benign':
                self.stats['benign_count'] += 1
            elif risk_category == 'suspicious':
                self.stats['suspicious_count'] += 1
            elif risk_category == 'malicious':
                self.stats['malicious_count'] += 1
            
            # Add to history (keep last 1000 scans)
            scan_entry = {
                'url': url,
                'risk': risk_category,
                'score': risk_score,
                'ml_prediction': ml_prediction,
                'timestamp': datetime.now().isoformat()
            }
            
            self.stats['scan_history'].append(scan_entry)
            
            # Trim history to last 1000 entries
            if len(self.stats['scan_history']) > 1000:
                self.stats['scan_history'] = self.stats['scan_history'][-1000:]
            
            self.stats['last_updated'] = datetime.now().isoformat()
            
            # Save to disk
            self._save_stats()
            
            return self.get_stats()
    
    def get_stats(self):
        """Get current statistics"""
        with self.lock:
            return {
                'total_scans': self.stats['total_scans'],
                'benign_count': self.stats['benign_count'],
                'suspicious_count': self.stats['suspicious_count'],
                'malicious_count': self.stats['malicious_count'],
                'last_updated': self.stats['last_updated'],
                'benign_percentage': round((self.stats['benign_count'] / self.stats['total_scans'] * 100) if self.stats['total_scans'] > 0 else 0, 1),
                'suspicious_percentage': round((self.stats['suspicious_count'] / self.stats['total_scans'] * 100) if self.stats['total_scans'] > 0 else 0, 1),
                'malicious_percentage': round((self.stats['malicious_count'] / self.stats['total_scans'] * 100) if self.stats['total_scans'] > 0 else 0, 1)
            }
    
    def get_recent_scans(self, limit=50):
        """Get recent scan history"""
        with self.lock:
            return self.stats['scan_history'][-limit:][::-1]  # Return most recent first
    
    def reset_stats(self):
        """Reset all statistics (admin function)"""
        with self.lock:
            self.stats = self._get_default_stats()
            self._save_stats()
            return self.get_stats()
