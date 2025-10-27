"""Windows Event Log parser module."""

from typing import Dict, List, Optional
from ..base_parser import BaseLogParser
from .windows_event_parser import WindowsEventParser

class WindowsLogParser(BaseLogParser):
    """Parser for Windows Event Log files."""
    
    def __init__(self):
        super().__init__()
        self.event_parser = WindowsEventParser()
    
    def parse_file(self, file_path: str) -> List[Dict[str, str]]:
        """Parse a Windows Event Log file."""
        return self.event_parser.parse_xml_file(file_path)
    
    def parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a single line of Windows Event Log."""
        return None
