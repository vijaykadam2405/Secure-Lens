"""
Base log parser module for common parsing functionality.
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Pattern

class BaseLogParser:
    """Base class for log parsers with common functionality."""
    
    # Common regex patterns for log parsing
    COMMON_PATTERNS = {
        'timestamp': r'(?:\d{4}-\d{2}-\d{2}|[A-Za-z]{3}\s+\d{1,2})\s+\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?',
        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'error': r'error|failure|failed|warn(?:ing)?|critical|invalid|denied|disconnect|timeout|attack|threat|compromise',
        'login': r'login|signin|auth(?:enticate)?|user|session|password|sudo|root|admin(?:istrator)?',
        'port': r'(?:port|dpt)[=\s]+(\d+)',
        'command': r'COMMAND=([^;]+)',
        'username': r'(?:user|USER)[=\s]+([^\s;]+)'
    }
    
    def __init__(self):
        """Initialize the parser with compiled regex patterns."""
        self.patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.COMMON_PATTERNS.items()
        }
    
    def parse_file(self, file_path: str) -> List[Dict[str, str]]:
        """Parse an entire log file."""
        results = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():  # Skip empty lines
                        parsed = self.parse_line(line)
                        if parsed:
                            results.append(parsed)
                        else:
                            # Try to parse line even if initial parsing failed
                            results.append({'raw_message': line.strip()})
        except Exception as e:
            print(f"Error parsing file {file_path}: {str(e)}")
        
        return results
    
    def parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a single line of log text. To be implemented by subclasses."""
        raise NotImplementedError
        
    def extract_pattern(self, pattern: Pattern, text: str) -> Optional[str]:
        """Extract a pattern from text safely."""
        match = pattern.search(text)
        return match.group(0) if match else None
        
    def extract_named_group(self, pattern: Pattern, text: str, group: str) -> Optional[str]:
        """Extract a named group from a pattern match."""
        match = pattern.search(text)
        return match.group(group) if match and group in match.groupdict() else None
        
    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse various timestamp formats into datetime object."""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%b %d %H:%M:%S',
            '%Y%m%d%H%M%S'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        return None