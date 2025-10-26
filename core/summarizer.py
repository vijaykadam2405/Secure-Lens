"""
Log summarization module with enhanced pattern-based analysis for security events.
"""

import re
from typing import Dict, List, Optional, Tuple

class LogSummarizer:
    """Summarizes log entries using pattern matching and security event analysis."""
    
    def __init__(self):
        # Common patterns for extracting information
        self.info_patterns = {
            'ip': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'timestamp': r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',
            'user': r'user[:\s]+(\w+)',
            'path': r'(?:\/[\w\-\.]+)+',
            'port': r'port\s+(\d+)',
        }
        
        # Security event patterns
        self.threat_patterns = {
            'login_failure': {
                'pattern': r'failed\s+password|invalid\s+user|authentication\s+failure|access\s+denied|login\s+failed',
                'summary': "Multiple failed login attempts detected",
                'level': 'medium'
            },
            'brute_force': {
                'pattern': r'repeated\s+failed|multiple\s+attempts|excessive\s+login|repeated\s+auth',
                'summary': "Potential brute force attack detected",
                'level': 'high'
            },
            'unauthorized_access': {
                'pattern': r'unauthorized|forbidden|403|permission\s+denied|access\s+violation',
                'summary': "Unauthorized access attempt detected",
                'level': 'high'
            },
            'suspicious_activity': {
                'pattern': r'suspicious|unusual|unexpected|anomaly|violation',
                'summary': "Suspicious activity detected",
                'level': 'medium'
            },
            'system_error': {
                'pattern': r'error|failure|failed|fatal|crash|exception',
                'summary': "System error or failure detected",
                'level': 'medium'
            },
            'port_activity': {
                'pattern': r'port\s+\d+|connection\s+from|connected\s+from',
                'summary': "Suspicious port activity detected",
                'level': 'medium'
            },
            'admin_access': {
                'pattern': r'root|admin|sudo|superuser|administrator',
                'summary': "Administrative access attempt detected",
                'level': 'high'
            }
        }
        
        # Compile all patterns for efficiency
        self.compiled_info_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.info_patterns.items()
        }
        
        self.compiled_threat_patterns = {
            name: re.compile(info['pattern'], re.IGNORECASE)
            for name, info in self.threat_patterns.items()
        }
    
    def extract_info(self, text: str) -> Dict[str, List[str]]:
        """Extract relevant information using regex patterns."""
        info = {}
        
        for key, pattern in self.info_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                info[key] = matches
        
        return info
    
    def analyze_threats(self, text: str) -> List[Dict[str, str]]:
        """
        Analyze text for security threats.
        Returns a list of detected threats with their patterns and levels.
        """
        threats = []
        for name, pattern in self.compiled_threat_patterns.items():
            if pattern.search(text):
                threats.append({
                    'type': name,
                    'summary': self.threat_patterns[name]['summary'],
                    'level': self.threat_patterns[name]['level']
                })
        return threats
    
    def summarize_threat(self, threat_data: Dict[str, str]) -> str:
        """
        Generate a human-readable summary of a threat.
        
        Args:
            threat_data: Dictionary containing threat information
            
        Returns:
            str: Formatted summary of the threat
        """
        message = threat_data.get('message', '')
        info = self.extract_info(message)
        threats = self.analyze_threats(message)
        
        # Format summary components
        summary_parts = []
        
        # Detected threats and severity
        if threats:
            highest_level = max(threat['level'] for threat in threats)
            threat_summaries = [threat['summary'] for threat in threats]
            summary_parts.append(f"Alert: {' | '.join(threat_summaries)}")
            summary_parts.append(f"Severity: {highest_level.upper()}")
        else:
            summary_parts.append(f"Alert: {threat_data.get('rule_name', 'Unknown threat').replace('_', ' ').title()}")
            summary_parts.append(f"Severity: {threat_data.get('threat_level', 'Unknown')}")
        
        # Timestamp
        if 'timestamp' in info:
            summary_parts.append(f"Time: {info['timestamp'][0]}")
            
        # User information
        if 'user' in info:
            summary_parts.append(f"User: {info['user'][0]}")
            
        # IP addresses
        if 'ip' in info:
            summary_parts.append(f"IPs: {', '.join(info['ip'])}")
            
        # Ports
        if 'port' in info:
            summary_parts.append(f"Ports: {', '.join(info['port'])}")
            
        # Paths
        if 'path' in info:
            summary_parts.append(f"Path: {info['path'][0]}")
        
        return " | ".join(summary_parts)
    
    def get_recommended_actions(self, threat_data: Dict[str, str]) -> List[str]:
        """Generate recommended actions based on detected threats."""
        actions = []
        message = threat_data.get('message', '')
        detected_threats = self.analyze_threats(message)
        
        # Get extracted information
        info = self.extract_info(message)
        ip_addresses = info.get('ip', [])
        users = info.get('user', [])
        
        for threat in detected_threats:
            threat_type = threat['type']
            
            if threat_type == 'brute_force':
                actions.extend([
                    "Block the source IP addresses" if ip_addresses else "Identify and block source IPs",
                    "Review authentication logs for patterns",
                    "Implement or strengthen rate limiting",
                    "Consider enabling multi-factor authentication"
                ])
            
            elif threat_type == 'login_failure':
                actions.extend([
                    "Review recent login attempts",
                    "Check for account lockout policies",
                    "Verify user credentials" if users else "Identify affected users"
                ])
            
            elif threat_type == 'port_scan':
                actions.extend([
                    "Block scanning IPs" if ip_addresses else "Identify and block scanning IPs",
                    "Review firewall rules and configurations",
                    "Enable IDS/IPS alerts for port scans",
                    "Consider implementing port knocking"
                ])
            
            elif threat_type == 'privilege_escalation':
                actions.extend([
                    "Review user permissions and roles",
                    "Check for unauthorized sudo/admin usage",
                    "Audit system access logs",
                    "Verify security group memberships"
                ])
            
            elif threat_type == 'malware':
                actions.extend([
                    "Isolate affected systems",
                    "Run full system scan",
                    "Update antivirus signatures",
                    "Check for unauthorized processes",
                    "Review network connections"
                ])
            
            elif threat_type == 'data_exfiltration':
                actions.extend([
                    "Monitor and analyze network traffic",
                    "Review data transfer logs",
                    "Check for unauthorized file access",
                    "Consider implementing DLP solutions",
                    "Review firewall egress rules"
                ])
            
            elif threat_type == 'injection':
                actions.extend([
                    "Review application logs",
                    "Check input validation controls",
                    "Update WAF rules",
                    "Scan for vulnerabilities",
                    "Review application security controls"
                ])
        
        # Add severity-based recommendations
        highest_level = max((threat['level'] for threat in detected_threats), default='low').upper()
        
        if highest_level == 'CRITICAL':
            actions.extend([
                "IMMEDIATE ACTION REQUIRED",
                "Notify security team and management",
                "Begin incident response procedures",
                "Document all actions taken"
            ])
        elif highest_level == 'HIGH':
            actions.extend([
                "Investigate within 1 hour",
                "Prepare incident report",
                "Alert security team"
            ])
        elif highest_level == 'MEDIUM':
            actions.extend([
                "Investigate within 24 hours",
                "Monitor for escalation"
            ])
        
        # Remove duplicates while preserving order
        seen = set()
        return [x for x in actions if not (x in seen or seen.add(x))]