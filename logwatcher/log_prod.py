# Previous content remains the same...

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