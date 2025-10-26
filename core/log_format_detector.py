"""
Log format detector to determine log type.
"""

import re
from typing import Dict, Optional
from .linux.linux_log_parser import LinuxLogParser
from .windows.windows_log_parser import WindowsLogParser
from .base_parser import BaseLogParser

class LogFormatDetector:
    """Detects the format and type of log files."""
    
    @staticmethod
    def detect_log_type(file_path: str) -> str:
        """
        Detect whether a log file contains Windows Event logs or Linux logs.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            'windows' or 'linux' based on the detected format
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read first few lines
                header = ''.join([next(f, '') for _ in range(5)])
                
                # Check for Windows Event Log XML format
                if '<?xml' in header or '<Event' in header or '<Events' in header:
                    return 'windows'
                
                # Check for typical Linux log patterns
                linux_patterns = [
                    r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',  # Syslog timestamp format
                    r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO timestamp format
                    r'systemd\[',
                    r'kernel:',
                    r'sshd\[',
                    r'sudo:',
                    r'authentication failure',
                    r'\[\s*\d+\.\d+\]'  # Kernel message timestamp
                ]
                
                if any(re.search(pattern, header) for pattern in linux_patterns):
                    return 'linux'
                
                # Default to Linux if no specific format detected
                return 'linux'
                
        except Exception as e:
            print(f"Error detecting log type: {str(e)}")
            return 'linux'  # Default to Linux format if detection fails
            
    def detect_format(self, file_path: str) -> str:
        """
        Detect the format of the log file.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Format of the log file ('windows' or 'linux')
        """
        return self.detect_log_type(file_path)
    
    def get_parser_for_format(self, log_format: str) -> BaseLogParser:
        """
        Get the appropriate parser for the detected log format.
        
        Args:
            log_format: The detected log format ('windows' or 'linux')
            
        Returns:
            An instance of the appropriate log parser
        """
        if log_format == 'windows':
            return WindowsLogParser()
        else:
            return LinuxLogParser()