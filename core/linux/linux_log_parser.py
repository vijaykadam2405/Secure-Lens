"""
Linux log parser module.
"""

from typing import Dict, List, Optional
import re
from ..base_parser import BaseLogParser

class LinuxLogParser(BaseLogParser):
    """Parser for Linux log file formats."""
    
    def __init__(self):
        # Common regex patterns for Linux log parsing
        self.patterns = {
            'timestamp': r'(?:\d{4}-\d{2}-\d{2}|[A-Za-z]{3}\s+\d{1,2})\s+\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?',
            'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'error': r'error|failure|failed|warn(?:ing)?|critical|invalid|denied|disconnect|timeout|attack|threat|compromise',
            'login': r'login|signin|auth(?:enticate)?|user|session|password|sudo|root|admin(?:istrator)?',
            'service': r'sshd|httpd|nginx|apache2?|mysql|postgresql|kernel|systemd|UFW|firewall|fail2ban',
            'port': r'(?:port|dpt)[=\s]+(\d+)',
            'command': r'COMMAND=([^;]+)',
            'username': r'(?:user|USER)[=\s]+([^\s;]+)'
        }
    
    def parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a single line of Linux log text."""
        if not line or not line.strip():
            return None
            
        line = line.strip()
        result = {}
        
        # Store raw message first
        result['raw_message'] = line
        
        # Extract timestamp
        timestamp_match = re.search(self.patterns['timestamp'], line, re.IGNORECASE)
        if timestamp_match:
            result['timestamp'] = timestamp_match.group(0)
        
        # Extract IP addresses
        ip_matches = re.findall(self.patterns['ip_address'], line)
        if ip_matches:
            result['ip_addresses'] = ip_matches
        
        # Extract service information
        service_match = re.search(self.patterns['service'], line, re.IGNORECASE)
        if service_match:
            result['service'] = service_match.group(0)
        
        # Extract port information
        port_match = re.search(self.patterns['port'], line, re.IGNORECASE)
        if port_match:
            result['port'] = port_match.group(0)
        
        # Check for errors or warnings
        error_match = re.search(self.patterns['error'], line, re.IGNORECASE)
        if error_match:
            result['event_type'] = 'error'
        
        # Check for login events
        login_match = re.search(self.patterns['login'], line, re.IGNORECASE)
        if login_match:
            result['event_type'] = 'login'
        
        return result