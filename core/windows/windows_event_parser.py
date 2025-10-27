"""
Windows Event Log implementation.
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from datetime import datetime

class WindowsEventParser:
    """Parser for Windows Event Log XML format."""
    
    def __init__(self):
        # Accumulator for partial XML data
        self._current_event = []
        self._in_event = False
        
        self.event_patterns = {
            'brute_force': ['4625', '4771'],  # Failed logon, Kerberos pre-authentication failed
            'privilege_escalation': ['4672', '4732', '4728', '4670', '4720'],  # Special privileges, Add user to privileged group
            'suspicious_execution': ['1'],  # Sysmon process creation
            'system_access': ['4663', '4656', '4658', '4660', '4657'],  # File/registry access
            'network_threat': ['3', '2004', '5156', '5157'],  # Network connection, Firewall block
            'account_manipulation': ['4720', '4722', '4723', '4724', '4725', '4726', '4738']  # Account management
        }
        
        self.critical_resources = [
            r'windows\\system32\\config\\sam',
            r'windows\\system32\\config\\security',
            r'windows\\system32\\config\\system',
            r'windows\\system32\\drivers\\etc\\hosts',
            r'programdata\\microsoft\\windows\\start menu',
            r'windows\\system32\\cmd.exe',
            r'windows\\system32\\powershell.exe'
        ]
        
        self.suspicious_commands = [
            'invoke-webrequest',
            'downloadstring',
            'iex(',
            'invoke-expression',
            'net user',
            'net localgroup',
            'mimikatz',
            'psexec',
            '-hidden',
            '-encode',
            '-enc',
            'bypass',
            'runas',
            'whoami'
        ]

    def parse_xml_file(self, file_path: str) -> List[Dict]:
        """Parse Windows Event Log XML file."""
        try:
            events = []
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    # Handle start of Events root element
                    if '<Events>' in line:
                        continue
                        
                    # Handle end of Events root element
                    if '</Events>' in line:
                        break
                        
                    # Handle start of Event element
                    if '<Event>' in line:
                        self._in_event = True
                        self._current_event = ['<?xml version="1.0" encoding="UTF-8"?>', line.strip()]
                        continue
                        
                    # Handle end of Event element
                    if '</Event>' in line:
                        if self._in_event:
                            self._current_event.append(line.strip())
                            event_xml = '\n'.join(self._current_event)
                            try:
                                root = ET.fromstring(event_xml)
                                parsed_event = self.parse_event(root)
                                if parsed_event:
                                    events.append(parsed_event)
                            except ET.ParseError as pe:
                                print(f"Error parsing event XML: {str(pe)}")
                            self._in_event = False
                            self._current_event = []
                        continue
                        
                    # Accumulate lines while inside an Event element
                    if self._in_event:
                        self._current_event.append(line.strip())
                    
            return events
        except Exception as e:
            print(f"Error parsing XML file: {str(e)}")
            return []

    def parse_event(self, event: ET.Element) -> Optional[Dict]:
        """Parse individual Windows Event."""
        try:
            # Get System elements
            system = event.find('System')
            if system is None:
                return None
                
            provider = system.find('Provider')
            event_id = system.find('EventID')
            level = system.find('Level')
            time_created = system.find('TimeCreated')
            computer = system.find('Computer')
            
            # Build basic event data
            event_data = {
                'provider': provider.get('Name') if provider is not None else None,
                'event_id': event_id.text if event_id is not None else None,
                'level': level.text if level is not None else None,
                'timestamp': time_created.get('SystemTime') if time_created is not None else None,
                'computer': computer.text if computer is not None else None,
                'event_type': self.determine_event_type(event),
                'data': {}
            }
            
            # Parse EventData
            event_data_elem = event.find('EventData')
            if event_data_elem is not None:
                for data in event_data_elem.findall('Data'):
                    name = data.get('Name')
                    if name:
                        event_data['data'][name] = data.text
                    elif data.text:
                        event_data['data']['Message'] = data.text
            
            # Add raw XML for reference
            event_data['raw_xml'] = ET.tostring(event, encoding='unicode')
            
            return event_data
            
        except Exception as e:
            print(f"Error parsing event: {str(e)}")
            return None

    def determine_event_type(self, event: ET.Element) -> str:
        """Determine the type of event based on EventID and content."""
        try:
            event_id = event.find('.//EventID')
            event_id_text = event_id.text if event_id is not None else None
            
            # Check event patterns
            for event_type, ids in self.event_patterns.items():
                if event_id_text in ids:
                    return event_type
            
            # Check for login events
            if event_id_text in ['4624', '4625', '4634', '4647']:
                return 'login'
            
            # Check for error events
            level = event.find('.//Level')
            if level is not None and level.text in ['1', '2', '3']:
                return 'error'
                
            # Check for system events
            if event_id_text and event_id_text.startswith('5'):
                return 'system'
                
            return 'unknown'
            
        except Exception as e:
            print(f"Error determining event type: {str(e)}")
            return 'unknown'

    def is_suspicious_command(self, command: str) -> bool:
        """Check if a command line contains suspicious patterns."""
        if not command:
            return False
        
        command_lower = command.lower()
        return any(pattern.lower() in command_lower for pattern in self.suspicious_commands)

    def is_critical_resource(self, path: str) -> bool:
        """Check if a file path contains critical system resources."""
        if not path:
            return False
            
        path_lower = path.lower()
        return any(resource.lower() in path_lower for resource in self.critical_resources)