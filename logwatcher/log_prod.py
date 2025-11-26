"""
LogWatcher - Real-time log file monitoring with pattern matching and notifications.
"""

import os
import sys
import time
import json
import re
import platform
import argparse
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import deque

# Platform-specific imports
if platform.system() == 'Windows':
    import win32file
    import win32con

if platform.system() == 'Linux':
    import inotify.adapters

from .config_validator import validate_config, DEFAULT_CONFIG
from .notifiers import NotificationManager
from .health_monitor import HealthMonitor
from .remote_syslog import RemoteSyslogManager


class BufferManager:
    """Manages context buffers for each monitored file."""

    def __init__(self, buffer_size: int = 20):
        self.buffer_size = buffer_size
        self.buffers: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def add_line(self, filename: str, line: str) -> None:
        """Add a line to the buffer for a specific file."""
        with self._lock:
            if filename not in self.buffers:
                self.buffers[filename] = deque(maxlen=self.buffer_size)
            self.buffers[filename].append(line)

    def get_context(self, filename: str) -> List[str]:
        """Get the current context buffer for a file."""
        with self._lock:
            if filename in self.buffers:
                return list(self.buffers[filename])
            return []


class RateLimiter:
    """Rate limiter for notifications."""

    def __init__(self, rate_limit_seconds: int = 60):
        self.rate_limit = rate_limit_seconds
        self.last_sent: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def can_send(self, key: str) -> bool:
        """Check if a notification can be sent for the given key."""
        with self._lock:
            now = datetime.now()
            if key not in self.last_sent:
                self.last_sent[key] = now
                return True

            elapsed = (now - self.last_sent[key]).total_seconds()
            if elapsed >= self.rate_limit:
                self.last_sent[key] = now
                return True
            return False


class Metrics:
    """Tracks metrics for the LogWatcher."""

    def __init__(self):
        self._lock = threading.Lock()
        self.data = {
            'matches_found': 0,
            'notifications_sent': 0,
            'errors': {},
            'pattern_matches': {},
            'last_match_time': None,
            'start_time': datetime.now()
        }

    def increment(self, key: str) -> None:
        """Increment a counter."""
        with self._lock:
            if key in self.data:
                self.data[key] += 1

    def add_error(self, error_type: str) -> None:
        """Record an error."""
        with self._lock:
            if error_type not in self.data['errors']:
                self.data['errors'][error_type] = 0
            self.data['errors'][error_type] += 1

    def add_pattern_match(self, pattern_name: str) -> None:
        """Record a pattern match."""
        with self._lock:
            if pattern_name not in self.data['pattern_matches']:
                self.data['pattern_matches'][pattern_name] = 0
            self.data['pattern_matches'][pattern_name] += 1

    def update_timestamp(self, key: str) -> None:
        """Update a timestamp field."""
        with self._lock:
            self.data[key] = datetime.now()


class NotificationQueue:
    """Async notification queue for handling notifications."""

    def __init__(self):
        self.queue: deque = deque()
        self._lock = threading.Lock()
        self.running = True
        self.thread = threading.Thread(target=self._process_queue, daemon=True)
        self.thread.start()

    def add_notification(self, notification: Dict[str, Any]) -> None:
        """Add a notification to the queue."""
        with self._lock:
            self.queue.append(notification)

    def _process_queue(self) -> None:
        """Process notifications from the queue."""
        logger = logging.getLogger("NotificationQueue")
        while self.running:
            notification = None
            with self._lock:
                if self.queue:
                    notification = self.queue.popleft()

            if notification:
                try:
                    handler = notification['handler']
                    if 'pattern' in notification:
                        handler(notification['pattern'], notification['message'])
                    else:
                        handler(notification['message'])
                except Exception as e:
                    logger.error(f"Error processing notification: {e}")
            else:
                time.sleep(0.1)

    def stop(self) -> None:
        """Stop the notification queue."""
        self.running = False


class LogWatcher:
    """Main LogWatcher class for monitoring log files."""

    def __init__(self, config_path: str, test_mode: bool = False):
        """
        Initialize the LogWatcher.

        Args:
            config_path: Path to the configuration file
            test_mode: If True, only output to stdout (no notifications)
        """
        self.test_mode = test_mode
        self.running = True
        self.stop_event = threading.Event()

        # Setup logging
        self.logger = logging.getLogger("LogWatcher")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Load and validate configuration
        self.config = self._load_config(config_path)

        # Initialize components
        self.metrics = Metrics()
        self.stats = self.metrics.data  # Alias for health monitor compatibility

        self.buffer_manager = BufferManager(
            buffer_size=self.config['settings'].get('buffer_size', 20)
        )

        self.rate_limiter = RateLimiter(
            rate_limit_seconds=self.config['settings'].get('notification_rate_limit', 60)
        )

        self.notification_manager = NotificationManager(self.config)
        self.syslog_manager = RemoteSyslogManager(self.config)
        self.notification_queue = NotificationQueue()

        # Compile patterns
        self.patterns = self._compile_patterns()
        self.file_patterns = self.config['file_patterns']

        # Initialize file tracking
        self.files = self._init_file_tracking()

        # Platform-specific handles
        self.win32_handles: Dict[str, Any] = {}
        self.notifier = None

        # Start health monitor
        self.health_monitor = HealthMonitor(self)
        self.health_thread = threading.Thread(target=self.health_monitor.run, daemon=True)
        self.health_thread.start()

        if test_mode:
            self.logger.info("Running in TEST MODE - notifications disabled")

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load and validate configuration from file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Merge with defaults
            merged_config = DEFAULT_CONFIG.copy()
            for key, value in config.items():
                if isinstance(value, dict) and key in merged_config:
                    merged_config[key].update(value)
                else:
                    merged_config[key] = value

            validate_config(merged_config)
            return merged_config
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            raise

    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns from configuration."""
        compiled = {}
        for name, pattern in self.config['patterns'].items():
            try:
                compiled[name] = re.compile(pattern)
            except re.error as e:
                self.logger.error(f"Invalid pattern '{name}': {e}")
                raise
        return compiled

    def _init_file_tracking(self) -> Dict[str, Dict[str, Any]]:
        """Initialize tracking info for all configured files."""
        files = {}
        for filename in self.file_patterns.keys():
            try:
                # Resolve to absolute path
                filepath = Path(filename).resolve()
                if not filepath.exists():
                    self.logger.warning(f"File not found: {filename}")
                    continue

                stat = filepath.stat()
                files[str(filepath)] = {
                    'pos': stat.st_size,  # Start at end of file
                    'inode': stat.st_ino,
                    'size': stat.st_size,
                    'last_read': datetime.now(),
                    'last_error': None,
                    'error_count': 0
                }
                self.logger.info(f"Tracking file: {filepath}")
            except Exception as e:
                self.logger.error(f"Error initializing file {filename}: {e}")

        # Update file_patterns with resolved paths
        resolved_patterns = {}
        for filename, patterns in self.file_patterns.items():
            resolved_path = str(Path(filename).resolve())
            if resolved_path in files:
                resolved_patterns[resolved_path] = patterns
        self.file_patterns = resolved_patterns

        return files

    def setup_watchers(self) -> None:
        """Setup platform-specific file watchers."""
        if platform.system() == 'Linux':
            self.setup_linux_watches()
        elif platform.system() == 'Windows':
            self.setup_win32_watches()

    def setup_linux_watches(self) -> None:
        """Setup file watches for Linux systems using inotify."""
        self.notifier = inotify.adapters.Inotify()
        for filename in self.files:
            try:
                dir_path = str(Path(filename).parent)
                self.notifier.add_watch(dir_path)
            except Exception as e:
                self.logger.error(f"Error setting up Linux watch for {filename}: {e}")
                self.metrics.add_error("linux_setup")
                self.files[filename]["last_error"] = str(e)
                self.files[filename]["error_count"] += 1

    def setup_win32_watches(self):
        """Setup file watches for Windows systems."""
        for filename in self.files:
            try:
                dir_path = str(Path(filename).parent)
                handle = win32file.CreateFile(
                    dir_path,
                    win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
                    None
                )
                self.win32_handles[filename] = handle
            except Exception as e:
                self.logger.error(f"Error setting up Windows watch for {filename}: {e}")
                self.metrics.add_error("win32_setup")
                self.files[filename]["last_error"] = str(e)
                self.files[filename]["error_count"] += 1

    def watch_files(self):
        """Main file watching loop."""
        self.setup_watchers()
        try:
            if platform.system() == 'Linux':
                self.watch_linux_files()
            elif platform.system() == 'Windows':
                self.watch_windows_files()
        except Exception as e:
            self.logger.exception("Error in watch_files:")
            self.metrics.add_error("watch_files")
            raise

    def watch_linux_files(self):
        """Watch files using inotify on Linux."""
        while self.running:
            try:
                for event in self.notifier.event_gen(yield_nones=False, timeout_s=1):
                    if self.stop_event.is_set():
                        break
                    (_, type_names, path, filename) = event
                    if 'IN_MODIFY' in type_names:
                        full_path = str(Path(path) / filename)
                        if full_path in self.files:
                            self.handle_file_change(full_path)
            except Exception as e:
                self.logger.exception("Error in Linux file watch:")
                self.metrics.add_error("linux_watch")
                time.sleep(1)

    def watch_windows_files(self):
        """Watch files using ReadDirectoryChangesW on Windows."""
        while self.running:
            for filename, handle in self.win32_handles.items():
                try:
                    results = win32file.ReadDirectoryChangesW(
                        handle,
                        1024,
                        False,
                        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,
                        None,
                        None
                    )
                    if results:
                        self.handle_file_change(filename)
                except Exception as e:
                    self.logger.exception(f"Error watching {filename}:")
                    self.metrics.add_error("windows_watch")
                    self.files[filename]["last_error"] = str(e)
                    self.files[filename]["error_count"] += 1
            if self.stop_event.wait(timeout=1):
                break

    def handle_file_change(self, filename: str):
        """Handle changes in monitored files."""
        try:
            current_stat = os.stat(filename)
            file_info = self.files[filename]

            # Check if file was rotated
            if current_stat.st_ino != file_info["inode"]:
                self.logger.info(f"File rotation detected for {filename}")
                file_info["pos"] = 0
                file_info["inode"] = current_stat.st_ino

            # Read new content
            with open(filename, 'r',
                     encoding=self.config['settings']['encoding']) as f:
                f.seek(file_info["pos"])

                while True:
                    chunk = f.read(self.config['settings']['read_chunk_size'])
                    if not chunk:
                        break

                    lines = chunk.splitlines()
                    if not lines:
                        continue

                    # Process lines and update buffer
                    for line in lines:
                        self.buffer_manager.add_line(filename, line)
                        # Process each line for pattern matches
                        for pattern_name in self.file_patterns[filename]:
                            if pattern_name in self.patterns:
                                if self.patterns[pattern_name].search(line):
                                    self.handle_match(pattern_name, line, filename)

                file_info["pos"] = f.tell()
                file_info["last_read"] = datetime.now()
                file_info["size"] = current_stat.st_size

        except Exception as e:
            self.logger.exception(f"Error processing {filename}:")
            self.metrics.add_error("file_processing")
            self.files[filename]["last_error"] = str(e)
            self.files[filename]["error_count"] += 1

    def handle_match(self, pattern_name: str, line: str, filename: str):
        """Handle a pattern match with notifications and rate limiting."""
        try:
            # Get context and prepare message
            context = self.buffer_manager.get_context(filename)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            message = (
                f"=== LogWatcher Match ===\n"
                f"Time: {timestamp}\n"
                f"File: {filename}\n"
                f"Pattern: {pattern_name}\n"
                f"Match: {line}\n"
                f"Recent context:\n{chr(10).join(context)}\n"
                f"======================="
            )

            # Update metrics
            self.metrics.increment('matches_found')
            self.metrics.add_pattern_match(pattern_name)
            self.metrics.update_timestamp('last_match_time')

            # Log the match
            self.logger.info(message)

            # Handle notifications if not in test mode
            if not self.test_mode:
                notification_key = f"{filename}:{pattern_name}"
                if self.rate_limiter.can_send(notification_key):
                    # Queue notifications asynchronously
                    self.notification_queue.add_notification({
                        'handler': self.notification_manager.notify,
                        'message': message,
                        'pattern': pattern_name
                    })

                    self.notification_queue.add_notification({
                        'handler': self.syslog_manager.send,
                        'message': message
                    })

                    self.metrics.increment('notifications_sent')
                else:
                    self.logger.debug(f"Rate limited notification for {notification_key}")

        except Exception as e:
            self.logger.exception("Error handling match:")
            self.metrics.add_error("match_handling")

    def cleanup(self) -> None:
        """Cleanup resources on shutdown."""
        self.logger.info("Shutting down LogWatcher...")
        self.running = False
        self.stop_event.set()

        # Stop health monitor
        self.health_monitor.stop()

        # Stop notification queue
        self.notification_queue.stop()

        # Close Windows handles
        for handle in self.win32_handles.values():
            try:
                handle.Close()
            except Exception:
                pass

        self.logger.info("LogWatcher shutdown complete")


def main():
    """Main entry point for the LogWatcher application."""
    parser = argparse.ArgumentParser(
        description="LogWatcher - Monitor log files for patterns"
    )
    parser.add_argument('config', help="Path to config file")
    parser.add_argument(
        '--test',
        action='store_true',
        help="Run in test mode (stdout only)"
    )
    args = parser.parse_args()

    watcher = None
    try:
        # Initialize and run LogWatcher
        watcher = LogWatcher(args.config, test_mode=args.test)
        watcher.watch_files()
    except Exception as e:
        logging.exception("Fatal error:")
        sys.exit(1)
    finally:
        if watcher:
            try:
                watcher.cleanup()
            except Exception as e:
                logging.exception("Error during cleanup:")

if __name__ == "__main__":
    main()
