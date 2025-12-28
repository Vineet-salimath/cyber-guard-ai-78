# Notification System for Security Events
# Integrates with existing app notification infrastructure

from typing import Dict, Optional, Callable, List
from datetime import datetime
import json
from enum import Enum

class NotificationLevel(Enum):
    """Notification severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

class NotificationChannel(Enum):
    """Delivery channels for notifications."""
    USER = "user"  # Send to specific user
    ADMIN = "admin"  # Send to admin/security dashboard
    BROADCAST = "broadcast"  # Send to all logged-in users
    EMAIL = "email"  # Send email notification

class NotificationService:
    """
    Central notification dispatcher for security events.
    Can route notifications to:
    - User in-app notifications
    - Admin/security dashboard
    - Email alerts
    - Socket.io broadcasts
    """
    
    def __init__(self):
        self.handlers: Dict[str, List[Callable]] = {
            NotificationChannel.USER.value: [],
            NotificationChannel.ADMIN.value: [],
            NotificationChannel.BROADCAST.value: [],
            NotificationChannel.EMAIL.value: []
        }
    
    def register_handler(self, channel: NotificationChannel, handler: Callable):
        """
        Register a handler for a notification channel.
        
        Handler signature: handler(event_data: Dict, recipient: str) -> None
        
        Args:
            channel: NotificationChannel enum
            handler: Callable that receives (event_data, recipient)
        """
        self.handlers[channel.value].append(handler)
    
    def notify_malicious_url_blocked(
        self,
        user_id: str,
        target_url: str,
        verdict: str,
        reason: str,
        risk_score: float,
        engine_detection_count: int = 0,
        engine_total_count: int = 0,
        threat_types: List[str] = None,
        notify_admin: bool = True
    ):
        """
        Send notification when a malicious URL is blocked.
        
        Args:
            user_id: User who clicked the malicious link
            target_url: The blocked URL
            verdict: 'malicious' or 'suspicious'
            reason: Reason for blocking
            risk_score: Risk score 0-100
            engine_detection_count: Number of engines detecting threat
            engine_total_count: Total antivirus engines checked
            threat_types: List of threat type strings
            notify_admin: Also notify admins
        """
        threat_types = threat_types or []
        
        event_data = {
            'event_type': 'malicious_url_blocked',
            'user_id': user_id,
            'target_url': target_url,
            'verdict': verdict,
            'reason': reason,
            'risk_score': risk_score,
            'engine_detection_count': engine_detection_count,
            'engine_total_count': engine_total_count,
            'threat_types': threat_types,
            'timestamp': datetime.utcnow().isoformat(),
            'severity': NotificationLevel.CRITICAL.value if verdict == 'malicious' else NotificationLevel.WARNING.value
        }
        
        # Notify the user
        self._dispatch(NotificationChannel.USER, event_data, user_id)
        
        # Notify admins
        if notify_admin:
            self._dispatch(NotificationChannel.ADMIN, event_data, 'security_team')
        
        # Broadcast to all (optional)
        # self._dispatch(NotificationChannel.BROADCAST, event_data, None)
    
    def notify_suspicious_url_access(
        self,
        user_id: str,
        target_url: str,
        risk_score: float
    ):
        """
        Send notification when a suspicious (but allowed) URL is accessed.
        """
        event_data = {
            'event_type': 'suspicious_url_warning',
            'user_id': user_id,
            'target_url': target_url,
            'risk_score': risk_score,
            'timestamp': datetime.utcnow().isoformat(),
            'severity': NotificationLevel.WARNING.value
        }
        
        self._dispatch(NotificationChannel.USER, event_data, user_id)
    
    def notify_invalid_url_attempt(
        self,
        user_id: str,
        attempted_url: str,
        error_reason: str
    ):
        """
        Send notification when user attempts to access an invalid URL.
        """
        event_data = {
            'event_type': 'invalid_url_attempt',
            'user_id': user_id,
            'attempted_url': attempted_url,
            'error_reason': error_reason,
            'timestamp': datetime.utcnow().isoformat(),
            'severity': NotificationLevel.INFO.value
        }
        
        self._dispatch(NotificationChannel.USER, event_data, user_id)
    
    def notify_admin_url_stats(
        self,
        total_blocked_today: int,
        unique_urls_blocked: int,
        top_threat_types: List[str],
        high_risk_users: List[str]
    ):
        """
        Send daily stats notification to admin/security team.
        """
        event_data = {
            'event_type': 'daily_url_stats',
            'total_blocked_today': total_blocked_today,
            'unique_urls_blocked': unique_urls_blocked,
            'top_threat_types': top_threat_types,
            'high_risk_users': high_risk_users,
            'timestamp': datetime.utcnow().isoformat(),
            'severity': NotificationLevel.INFO.value
        }
        
        self._dispatch(NotificationChannel.ADMIN, event_data, 'security_team')
    
    def _dispatch(self, channel: NotificationChannel, event_data: Dict, recipient: Optional[str]):
        """
        Internal method to dispatch notifications to registered handlers.
        
        Args:
            channel: NotificationChannel enum
            event_data: Event data dict
            recipient: Recipient user_id or group identifier
        """
        handlers = self.handlers.get(channel.value, [])
        
        for handler in handlers:
            try:
                handler(event_data, recipient)
            except Exception as e:
                print(f"[NotificationService] Handler error on {channel.value}: {e}")

# Global notification service instance
_notification_service: Optional[NotificationService] = None

def init_notification_service() -> NotificationService:
    """Initialize and return the global notification service."""
    global _notification_service
    if _notification_service is None:
        _notification_service = NotificationService()
    return _notification_service

def get_notification_service() -> NotificationService:
    """Get the global notification service instance."""
    global _notification_service
    if _notification_service is None:
        _notification_service = NotificationService()
    return _notification_service
