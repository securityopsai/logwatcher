import time
import threading
import logging
from typing import Dict, Any
from datetime import datetime, timedelta

class HealthMonitor:
    def __init__(self, log_watcher, check_interval: int = 60):
        """
        Initialize the health monitor.
        
        Args:
            log_watcher: Reference to the LogWatcher instance
            check_interval: How often to run health checks (in seconds)
        """
        self.log_watcher = log_watcher
        self.check_interval = check_interval
        self.logger = logging.getLogger("HealthMonitor")
        self.running = True
        self.last_check = None
        self.health_status = {}
        self._lock = threading.Lock()

    def stop(self):
        """Stop the health monitoring thread."""
        self.running = False

    def run(self):
        """Main monitoring loop."""
        while self.running:
            try:
                self.check_health()
                time.sleep(self.check_interval)
            except Exception as e:
                self.logger.error(f"Error in health check: {e}")
                time.sleep(5)  # Short delay on error

    def check_health(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check of the LogWatcher system.
        
        Returns:
            Dict containing health status information
        """
        with self._lock:
            now = datetime.now()
            status = {
                'timestamp': now.isoformat(),
                'uptime': str(now - self.log_watcher.stats['start_time']),
                'system_status': 'healthy',
                'components': {}
            }

            # Check file monitoring
            status['components']['file_monitoring'] = self._check_file_monitoring()

            # Check notification systems
            status['components']['notifications'] = (
                self.log_watcher.notification_manager.check_health()
            )

            # Check syslog connection
            status['components']['syslog'] = self._check_syslog()

            # Check statistics
            status['statistics'] = {
                'matches_found': self.log_watcher.stats['matches_found'],
                'notifications_sent': self.log_watcher.stats['notifications_sent'],
                'errors_encountered': self.log_watcher.stats['errors_encountered']
            }

            # Determine overall system health
            if self._has_critical_issues(status):
                status['system_status'] = 'degraded'

            self.health_status = status
            self.last_check = now
            
            self._log_health_status(status)
            return status

    def _check_file_monitoring(self) -> Dict[str, Any]:
        """Check the health of file monitoring."""
        file_status = {}
        for filename, info in self.log_watcher.files.items():
            file_health = {
                'status': 'healthy',
                'last_read': info['last_read'].isoformat(),
                'error_count': info['error_count'],
                'last_error': info['last_error']
            }

            # Check if file hasn't been read recently
            if datetime.now() - info['last_read'] > timedelta(minutes=5):
                file_health['status'] = 'warning'
                file_health['message'] = 'No recent reads'

            # Check if file has errors
            if info['error_count'] > 0:
                file_health['status'] = 'error'
                
            file_status[filename] = file_health

        return file_status

    def _check_syslog(self) -> Dict[str, str]:
        """Check syslog connectivity."""
        try:
            if not self.log_watcher.syslog_manager.enabled:
                return {'status': 'disabled'}
            
            # Attempt to send test message
            self.log_watcher.syslog_manager.send("Health check test message")
            return {'status': 'healthy'}
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }

    def _has_critical_issues(self, status: Dict[str, Any]) -> bool:
        """
        Determine if there are any critical health issues.
        
        Args:
            status: Health status dictionary
            
        Returns:
            True if there are critical issues, False otherwise
        """
        # Check file monitoring
        for file_status in status['components']['file_monitoring'].values():
            if file_status['status'] == 'error':
                return True

        # Check notifications
        for notifier_status in status['components']['notifications'].values():
            if notifier_status.startswith('ERROR'):
                return True

        # Check syslog if enabled
        syslog_status = status['components']['syslog']
        if syslog_status['status'] == 'error' and syslog_status != 'disabled':
            return True

        return False

    def _log_health_status(self, status: Dict[str, Any]):
        """Log health status information at appropriate levels."""
        if status['system_status'] == 'healthy':
            self.logger.info("Health check passed: System healthy")
        else:
            self.logger.warning(
                "Health check warning: System degraded\n" +
                f"Status: {status}"
            )

        # Log any specific component issues
        for component, details in status['components'].items():
            if isinstance(details, dict):
                for item, item_status in details.items():
                    if isinstance(item_status, dict) and item_status.get('status') == 'error':
                        self.logger.error(
                            f"Component {component} - {item} is in error state: "
                            f"{item_status.get('message', 'No error message')}"
                        )