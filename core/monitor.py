"""
Real-time log monitoring system.
"""

import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Callable
from pathlib import Path
import threading

class LogMonitor(FileSystemEventHandler):
    """Monitor a single log file for changes."""
    
    def __init__(self, file_path: str, callback: Callable[[str, str], None]):
        """
        Initialize the log monitor.
        
        Args:
            file_path: Path to the log file to monitor
            callback: Function to call when new log entries are detected
        """
        self.file_path = os.path.abspath(file_path)
        self.dir_path = os.path.dirname(self.file_path)
        self.callback = callback
        self.observer = Observer()
        self.position = 0
        self.running = False
        self.check_interval = 0.1  # 100ms
        self.monitor_thread = None
        
    def on_modified(self, event):
        """Called when the monitored file is modified."""
        if not event.is_directory and event.src_path == self.file_path:
            self._process_file()
    
    def _process_file(self):
        """Process new content in the log file."""
        try:
            # Check if file exists
            if not os.path.exists(self.file_path):
                print(f"Warning: File {self.file_path} does not exist")
                return

            # Check if file has been rotated
            current_size = os.path.getsize(self.file_path)
            if current_size < self.position:
                # File has been rotated or truncated, reset position
                self.position = 0
                print(f"Log rotation detected for {self.file_path}")

            with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
                # Seek to last known position
                f.seek(self.position)
                
                # Read new content in chunks to handle large files
                chunk_size = 8192  # 8KB chunks
                new_content = []
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    new_content.append(chunk)

                if new_content:
                    # Update position before callback to prevent missing content
                    self.position = f.tell()
                    self.callback(self.file_path, ''.join(new_content))
                
        except PermissionError:
            print(f"Permission denied accessing file {self.file_path}")
        except UnicodeDecodeError:
            print(f"Unicode decode error in file {self.file_path}")
        except Exception as e:
            print(f"Error processing file {self.file_path}: {str(e)}")
    
    def _monitor_loop(self):
        """Background thread to actively check for file changes."""
        while self.running:
            self._process_file()
            time.sleep(self.check_interval)
    
    def start(self):
        """Start monitoring the log file."""
        # Initialize starting position
        try:
            self.position = os.path.getsize(self.file_path)
        except:
            self.position = 0
        
        # Start file system observer
        self.observer.schedule(self, self.dir_path, recursive=False)
        self.observer.start()
        
        # Start active monitoring thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop(self):
        """Stop monitoring the log file."""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        self.observer.stop()
        self.observer.join()