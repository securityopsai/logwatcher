import socket
import logging
import logging.handlers
import threading
import time
from typing import Dict, Optional
from datetime import datetime

class RemoteSyslogManager:
    """Enhanced Remote Syslog Manager with connection management and retry logic."""
    
    FACILITIES = {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
        'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
        'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23
    }

    def __init__(self, config: Dict):
        """
        Initialize the RemoteSyslogManager.
        
        Args:
            config: Configuration dictionary containing syslog settings
        """
        self.config = config.get('notifications', {}).get('syslog', {})
        self.enabled = self.config.get('enabled', False)
        self.logger = logging.getLogger("RemoteSyslogManager")
        self._lock = threading.Lock()
        self._handler: Optional[logging.handlers.SysLogHandler] = None
        self._last_error: Optional[str] = None
        self._error_count = 0
        self._last_successful_send: Optional[datetime] = None
        
        if not self.enabled:
            return

        self._initialize_handler()

    def _initialize_handler(self) -> None:
        """Initialize or reinitialize the syslog handler."""
        try:
            facility = self.config.get('facility', 'local0')
            if facility not in self.FACILITIES:
                facility = 'local0'
                self.logger.warning(
                    f"Invalid facility {facility}, defaulting to local0"
                )

            socktype = (socket.SOCK_DGRAM 
                       if self.config.get('protocol', 'udp').lower() == 'udp'
                       else socket.SOCK_STREAM)

            with self._lock:
                if self._handler is not None:
                    self._handler.close()

                self._handler = logging.handlers.SysLogHandler(
                    address=(self.config['host'], self.config['port']),
                    facility=self.FACILITIES[facility],
                    socktype=socktype
                )
                
                self._logger = logging.getLogger(self.config.get('tag', 'logwatcher'))
                self._logger.addHandler(self._handler)
                self._logger.setLevel(logging.INFO)
                
                self._last_error = None
                self._last_successful_send = datetime.now()

        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            raise

    def send(self, message: str, level: int = logging.INFO, 
             max_retries: int = 3) -> bool:
        """
        Send a message to the remote syslog with retry logic.
        
        Args:
            message: Message to send
            level: Logging level
            max_retries: Maximum number of retry attempts
            
        Returns:
            bool: True if message was sent successfully, False otherwise
        """
        if not self.enabled:
            return False

        retries = 0
        while retries < max_retries:
            try:
                with self._lock:
                    if self._handler is None:
                        self._initialize_handler()
                    self._logger.log(level, message)
                    self._last_successful_send = datetime.now()
                    return True
            except Exception as e:
                retries += 1
                self._last_error = str(e)
                self._error_count += 1
                
                if retries < max_retries:
                    self.logger.warning(
                        f"Syslog send failed (attempt {retries}/{max_retries}): {e}"
                    )
                    time.sleep(1)  # Wait before retry
                    try:
                        self._initialize_handler()  # Try to reinitialize
                    except Exception as init_error:
                        self.logger.error(
                            f"Failed to reinitialize syslog handler: {init_error}"
                        )
                else:
                    self.logger.error(f"Failed to send message to syslog: {e}")
        
        return False

    def get_status(self) -> Dict:
        """
        Get the current status of the syslog connection.
        
        Returns:
            Dict containing status information
        """
        if not self.enabled:
            return {'status': 'disabled'}

        status = {
            'status': 'healthy' if self._last_error is None else 'error',
            'error_count': self._error_count,
            'last_error': self._last_error,
            'last_successful_send': (
                self._last_successful_send.isoformat() 
                if self._last_successful_send else None
            )
        }

        return status

    def __del__(self):
        """Cleanup handler on deletion."""
        if self._handler:
            try:
                self._handler.close()
            except Exception as e:
                self.logger.error(f"Error closing syslog handler: {e}")
