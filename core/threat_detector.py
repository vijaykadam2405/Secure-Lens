"""
Threat detection rules and scoring system.
"""

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from .summarizer import LogSummarizer
from .log_format_detector import LogFormatDetector
from .windows.windows_event_detector import WINDOWS_EVENT_DETECTORS
from .windows.windows_log_parser import WindowsEventParser
from .linux.linux_detectors import LINUX_DETECTORS
from .linux.linux_log_parser import LinuxLogParser

class ThreatLevel:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class ThreatDetector:
    """Detects and scores potential security threats in log entries."""
    
    def __init__(self):
        self.summarizer = LogSummarizer()
        self.windows_parser = WindowsEventParser()
        self.linux_parser = LinuxLogParser()
        self.format_detector = LogFormatDetector()
    
    def analyze_log_entry(self, log_entry: Dict[str, str]) -> Optional[Dict[str, str]]:
        """
        Analyze a single log entry for potential threats using all available detectors.
        
        Args:
            log_entry: Dictionary containing parsed log data
            
        Returns:
            Dictionary with threat information if detected, None otherwise
        """
        if not log_entry:
            return None
        
        detected_threats = []
        
        # Check if this is a Windows Event Log entry
        raw_message = log_entry.get('raw_message', '')
        raw_xml = log_entry.get('raw_xml', '')
        if raw_xml or '<Event>' in raw_message or '<s>' in raw_message or '<EventData>' in raw_message:
            try:
                # Extract event data from the log entry
                event_data = {
                    'event_id': None,
                    'provider': None,
                    'data': {},
                    'raw_xml': raw_message
                }
                
                # Try to extract EventID
                if '<EventID>' in raw_message:
                    event_id_match = re.search(r'<EventID>(\d+)</EventID>', raw_message)
                    if event_id_match:
                        event_data['event_id'] = event_id_match.group(1)
                
                # Try to extract Provider
                if 'Provider Name=' in raw_message:
                    provider_match = re.search(r'Provider Name="([^"]+)"', raw_message)
                    if provider_match:
                        event_data['provider'] = provider_match.group(1)
                
                # Try to extract Data elements
                data_matches = re.findall(r'<Data Name="([^"]+)">([^<]+)</Data>', raw_message)
                for name, value in data_matches:
                    event_data['data'][name] = value
                
                        # Process with Windows event detectors
                for detector in WINDOWS_EVENT_DETECTORS:
                    try:
                        result = detector(event_data)
                        if result:
                            # Ensure required fields are present
                            result['source_ip'] = (
                                event_data.get('data', {}).get('IpAddress') or
                                event_data.get('data', {}).get('SourceIp') or
                                event_data.get('data', {}).get('RemoteAddress')
                            )
                            result['timestamp'] = event_data.get('timestamp') or log_entry.get('timestamp')
                            detected_threats.append(result)
                    except Exception as e:
                        print(f"Error in Windows detector {detector.__name__}: {str(e)}")
                        continue
                        
            except Exception as e:
                print(f"Error parsing Windows event: {str(e)}")
        
        # Run standard detectors based on log type
        detectors = LINUX_DETECTORS  # Default to Linux detectors
        
        if raw_xml or raw_message.startswith('<?xml') or '<Event>' in raw_message:
            detectors = WINDOWS_EVENT_DETECTORS
            
        for detector in detectors:
            try:
                result = detector(log_entry)
                if result:
                    print(f"Debug: Detector {detector.__name__} found threat: {result}")
                    detected_threats.append(result)
            except Exception as e:
                print(f"Error in {detector.__name__}: {str(e)}")
                continue
        
        if not detected_threats:
            return None
            
        # Get the highest severity threat
        highest_threat = max(detected_threats, key=lambda x: self._threat_level_value(x['level']))
        
        # Extract service information if available
        raw_message = log_entry.get('raw_message', '')
        service_match = re.search(r'(\w+)\[\d+\]:', raw_message)
        service = service_match.group(1) if service_match else log_entry.get('service')
        
        # Extract port information
        port_match = re.search(r'port\s+(\d+)', raw_message)
        port = port_match.group(1) if port_match else log_entry.get('port')
        
        # Get IP addresses from log entry
        ip_addresses = log_entry.get('ip_addresses', [])
        
        # Build comprehensive threat data
        threat_data = {
            'rule_name': highest_threat['type'],
            'threat_level': highest_threat['level'],
            'message': raw_message,
            'timestamp': log_entry.get('timestamp'),
            'source_ip': ip_addresses[0] if ip_addresses else None,
            'service': service,
            'port': port,
            'summary': highest_threat['summary'],
            'all_detected_threats': [t['summary'] for t in detected_threats]
        }
        
        # Add detailed analysis
        threat_data['detected_threats'] = [t['summary'] for t in detected_threats]
        threat_data['recommended_actions'] = self.summarizer.get_recommended_actions(threat_data)
        
        return threat_data
    
    def _threat_level_value(self, level: str) -> int:
        """Convert threat level string to numeric value for comparison."""
        levels = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return levels.get(level.lower(), 0)
    
    def get_threat_summary(self, threats: List[Dict[str, str]]) -> str:
        """Generate a detailed summary of detected threats."""
        if not threats:
            return "No threats detected."
            
        # Get highest severity
        highest_threat = max(threats, key=lambda x: self._threat_level_value(x['threat_level']))
        
        # Group threats by type and level
        threat_groups = {}
        for threat in threats:
            level = threat['threat_level']
            threat_type = threat.get('rule_name', 'unknown')
            summary = threat.get('summary', '')
            source = threat.get('source_ip', 'unknown source')
            key = f"{level}:{threat_type}"
            
            if key not in threat_groups:
                threat_groups[key] = {
                    'level': level,
                    'type': threat_type,
                    'count': 0,
                    'details': []
                }
            
            threat_groups[key]['count'] += 1
            if summary:  # Only add if there's a summary
                threat_groups[key]['details'].append(f"{summary} from {source}")
        
        # Build summary
        lines = []
        lines.append(f"====== Threats Detected ======")
        lines.append(f"Alert Summary: {len(threats)} threats detected (Highest severity: {highest_threat['threat_level']})")
        lines.append("")
        
        # Count threats by level
        level_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for group in threat_groups.values():
            level_counts[group['level']] += group['count']
            
        # Show count summary
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if level_counts[level] > 0:
                lines.append(f"{level_counts[level]}x {level} threat(s)")
                
        lines.append("\nDetailed Threat Analysis:\n")
        
        # Show detailed breakdown by type and severity
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            level_threats = {k: v for k, v in threat_groups.items() if v['level'] == level}
            if level_threats:
                lines.append(f"{level} Severity Threats:")
                for threat_key, threat_data in level_threats.items():
                    lines.append(f"\nThreat Type: {threat_data['type'].replace('_', ' ').title()}")
                    lines.append(f"Count: {threat_data['count']}")
                    lines.append("Details:")
                    for detail in threat_data['details']:
                        lines.append(f"- {detail}")
                lines.append("")
                
        return "\n".join(lines)
        
        # Group threats by level and type, preserving original summaries
        for threat in threats:
            level = threat['threat_level']
            if 'summary' in threat:
                key = f"{level}:{threat['summary']}"
            elif 'detected_threats' in threat:
                for detected in threat['detected_threats']:
                    key = f"{level}:{detected}"
                    threat_counts[key] = threat_counts.get(key, 0) + 1
                continue
            else:
                key = f"{level}:{threat.get('rule_name', 'Unknown threat')}"
            threat_counts[key] = threat_counts.get(key, 0) + 1
        
        # Sort by severity and count
        sorted_threats = sorted(
            threat_counts.items(),
            key=lambda x: (-self._threat_level_value(x[0].split(':')[0]), -x[1])
        )
        
        # Calculate total threats and highest severity
        total_threats = sum(threat_counts.values())
        if total_threats > 0:
            highest_level = max(
                (k.split(':')[0] for k in threat_counts.keys()),
                key=self._threat_level_value
            )
            summary_parts.append(
                f"Alert Summary: {total_threats} threats detected "
                f"(Highest severity: {highest_level})"
            )
        
        # Add individual threat summaries
        for key, count in sorted_threats:
            level, description = key.split(':')
            summary_parts.append(
                f"{count}x {level} threat(s): {description}"
            )
        
        return "\n".join(summary_parts)
        
        # Sort by severity first, then by count
        sorted_threats = sorted(
            threat_counts.items(),
            key=lambda x: (-self._threat_level_value(x[0].split(':')[0]), -x[1])
        )
        
        # Generate summary lines
        for key, count in sorted_threats:
            level, description = key.split(':')
            summary.append(
                f"{count}x {level} threat(s): {description.replace('_', ' ').title()}"
            )
        
        # Add overall assessment
        if summary:
            highest_level = max(
                (key.split(':')[0] for key in threat_counts.keys()),
                key=self._threat_level_value
            )
            total_threats = sum(threat_counts.values())
            summary.insert(0, f"Alert Summary: {total_threats} threats detected "
                            f"(Highest severity: {highest_level})")
            
        return "\n".join(summary)