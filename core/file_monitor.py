"""
Common file monitoring functionality.
"""

import os
import time
from typing import Dict, Optional, List, Callable
from threading import Thread, Event
from queue import Queue
from datetime import datetime
from .log_format_detector import LogFormatDetector

class FileMonitor:
    """Monitors log files for changes and processes new content."""
    
    def __init__(self, callback: Callable[[str], None]):
        """
        Initialize the file monitor.
        
        Args:
            callback: Function to call when new log entries are detected
        """
        self.callback = callback
        self.stop_event = Event()
        self.monitor_thread: Optional[Thread] = None
        self.current_file: Optional[str] = None
        self.alert_queue = Queue()
        
    def start_monitoring(self, file_path: str) -> bool:
        """
        Start monitoring a specific log file.
        
        Args:
            file_path: Path to the log file to monitor
            
        Returns:
            bool: True if monitoring started successfully
        """
        if not os.path.exists(file_path):
            return False
            
        # Stop any existing monitoring
        self.stop_monitoring()
        
        self.current_file = file_path
        self.stop_event.clear()
        
        # Start monitoring thread
        self.monitor_thread = Thread(
            target=self._monitor_file,
            args=(file_path,),
            daemon=True
        )
        self.monitor_thread.start()
        return True
        
    def stop_monitoring(self):
        """Stop monitoring the current file."""
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.stop_event.set()
            self.monitor_thread.join()
            
        self.current_file = None
        self.monitor_thread = None
        
    def _monitor_file(self, file_path: str):
        """
        Continuously monitor a file for new content.
        
        Args:
            file_path: Path to the file to monitor
        """
        try:
            with open(file_path, 'r') as f:
                # Seek to end of file
                f.seek(0, 2)
                
                while not self.stop_event.is_set():
                    # Get current position
                    current_pos = f.tell()
                    
                    # Read new line if available
                    line = f.readline()
                    if line:
                        # Process new line
                        self.callback(line.strip())
                    else:
                        # No new data, wait briefly
                        time.sleep(0.1)
                        
                        # Check if file has been truncated
                        f.seek(0, 2)
                        if f.tell() < current_pos:
                            f.seek(0)
                            
        except Exception as e:
            print(f"Error monitoring file {file_path}: {str(e)}")
            
    def is_monitoring(self) -> bool:
        """Check if currently monitoring a file."""
        return bool(self.monitor_thread and self.monitor_thread.is_alive())
        
    def get_current_file(self) -> Optional[str]:
        """Get the path of the currently monitored file."""
        return self.current_file