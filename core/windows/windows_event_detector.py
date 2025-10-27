"""
Windows Event Log threat detector module.
"""
from typing import Dict, Optional
import re
import xml.etree.ElementTree as ET

def parse_windows_event(event_xml: str) -> Dict:
    """Parse Windows Event XML into a structured format."""
    try:
        root = ET.fromstring(event_xml)
        event_data = {
            'EventID': root.find('.//EventID').text if root.find('.//EventID') is not None else None,
            'Level': root.find('.//Level').text if root.find('.//Level') is not None else None,
            'TimeCreated': root.find('.//TimeCreated').get('SystemTime') if root.find('.//TimeCreated') is not None else None,
            'Provider': root.find('.//Provider').get('Name') if root.find('.//Provider') is not None else None,
            'Computer': root.find('.//Computer').text if root.find('.//Computer') is not None else None,
            'Data': {}
        }
        
        # Extract all Data elements
        for data in root.findall('.//EventData/Data'):
            if 'Name' in data.attrib:
                event_data['Data'][data.attrib['Name']] = data.text
            elif data.text:
                event_data['Data']['Message'] = data.text
                
        return event_data
    except Exception as e:
        print(f"Error parsing Windows event: {str(e)}")
        return {}

def windows_brute_force_detector(event_data: Dict) -> Optional[Dict]:
    """Detect brute force attacks from Windows events."""
    event_id = event_data.get('event_id')
    provider = event_data.get('provider', '')
    data = event_data.get('data', {})
    raw_xml = event_data.get('raw_xml', '').lower()
    
    # Check for failed login attempts
    if event_id == '4625':  # Failed logon
        ip = data.get('IpAddress', 'unknown')
        user = data.get('TargetUserName', 'unknown')
        status = data.get('Status', '')
        return {
            'type': 'brute_force',
            'level': 'HIGH',
            'summary': f"Failed login attempt detected from IP {ip} for user {user}"
        }
    elif event_id == '4771':  # Kerberos pre-authentication failed
        user = data.get('TargetUserName', 'unknown')
        return {
            'type': 'brute_force_kerberos',
            'level': 'HIGH',
            'summary': f"Kerberos pre-authentication failed for user {user}"
        }
    # Check for brute force alerts in custom SIEM alerts
    elif provider == 'Custom-SIEM-Alert' and ('multiple failed' in raw_xml or 'brute force' in raw_xml):
        alert = data.get('Alert', 'Unknown alert')
        return {
            'type': 'brute_force',
            'level': 'HIGH',
            'summary': alert
        }
    return None

def windows_privilege_escalation_detector(event_data: Dict) -> Optional[Dict]:
    """Detect privilege escalation attempts."""
    event_id = event_data.get('event_id')
    provider = event_data.get('provider', '')
    data = event_data.get('data', {})
    raw_xml = event_data.get('raw_xml', '').lower()
    
    if provider == 'Custom-SIEM-Alert' and 'privilege escalation' in raw_xml:
        user = data.get('User', 'unknown')
        command = data.get('Command', 'unknown')
        return {
            'type': 'privilege_escalation',
            'level': 'HIGH',
            'summary': f"Privilege escalation detected for user {user} using command: {command}"
        }
    elif event_id == '4720':  # New user account created
        account = data.get('NewAccountName', 'unknown')
        privileges = data.get('Privileges', 'unknown')
        return {
            'type': 'account_creation',
            'level': 'HIGH',
            'summary': f"New account '{account}' created with {privileges} privileges"
        }
    elif event_id == '4672':  # Special privileges assigned
        user = data.get('SubjectUserName', 'unknown')
        return {
            'type': 'privilege_escalation',
            'level': 'HIGH',
            'summary': f"Special privileges assigned to user {user}"
        }
    elif event_id == '4670':  # Permissions modified on sensitive files
        user = data.get('SubjectUserName', 'unknown')
        object_name = data.get('ObjectName', 'unknown')
        return {
            'type': 'system_modification',
            'level': 'HIGH',
            'summary': f"System permissions modified on {object_name} by user {user}"
        }
    return None

def windows_malware_detector(event_data: Dict) -> Optional[Dict]:
    """Detect potential malware activity."""
    event_id = event_data.get('event_id')
    provider = event_data.get('provider', '')
    data = event_data.get('data', {})
    raw_xml = event_data.get('raw_xml', '').lower()
    
    # Suspicious PowerShell/Process patterns
    suspicious_patterns = [
        'invoke-webrequest', 'downloadstring', 'payload.exe', 'malicious',
        'iex(', 'invoke-expression', 'net user', 'mimikatz', 'psexec',
        '-hidden', '-encode', '-enc', 'bypass', 'runas', 'whoami',
        'base64', 'certutil -decode', 'vssadmin delete', 'reg delete',
        'rundll32', 'regsvr32', 'javascript:', 'vbscript:', 'ws.run'
    ]
    
    # Suspicious file extensions and names
    suspicious_files = [
        'backdoor', 'payload', 'hack', '.ps1', '.vbs', '.bat', '.exe',
        '.dll', '.scr', '.jar', '.js', '.hta', '.msi', 'temp\\', 'public\\'
    ]
    
    if event_id == '1' and 'sysmon' in provider.lower():  # Process creation
        cmdline = data.get('CommandLine', '').lower()
        image = data.get('Image', '').lower()
        user = data.get('User', 'unknown')
        
        for pattern in suspicious_patterns:
            if pattern in cmdline:
                return {
                    'type': 'malware',
                    'level': 'CRITICAL',
                    'summary': f"Suspicious command execution by {user}",
                    'details': {
                        'process': image,
                        'command': cmdline,
                        'pattern': pattern
                    }
                }
                
    elif event_id == '11':  # File creation
        filename = data.get('FileName', '').lower()
        user = data.get('User', 'unknown')
        
        for pattern in suspicious_files:
            if pattern in filename:
                return {
                    'type': 'malware',
                    'level': 'HIGH',
                    'summary': f"Suspicious file '{filename}' created by {user}",
                    'details': {
                        'file': filename,
                        'pattern': pattern
                    }
                }
                
    # Check for PowerShell script content alerts
    elif provider == 'Custom-SIEM-Alert' and any(x in raw_xml for x in ['malware', 'virus', 'trojan', 'ransomware', 'backdoor']):
        alert = data.get('Alert', 'Unknown malware alert')
        severity = data.get('Severity', 'HIGH')
        return {
            'type': 'malware',
            'level': severity,
            'summary': alert
        }
        
    return None

def windows_suspicious_network_detector(event_data: Dict) -> Optional[Dict]:
    """Detect suspicious network activity."""
    event_id = event_data.get('event_id')
    provider = event_data.get('provider', '')
    data = event_data.get('data', {})
    raw_xml = event_data.get('raw_xml', '').lower()
    
    if event_id == '3' and provider == 'Microsoft-Windows-Sysmon':  # Network connection
        try:
            bytes_transferred = int(data.get('Bytes', 0))
            dest_ip = data.get('DestinationIp', 'unknown')
            dest_port = data.get('DestinationPort', 'unknown')
            if bytes_transferred > 1000000:  # Large data transfer (>1MB)
                return {
                    'type': 'data_exfiltration',
                    'level': 'HIGH',
                    'summary': f"Large data transfer detected: {bytes_transferred} bytes to {dest_ip}:{dest_port}"
                }
        except ValueError:
            pass
    elif provider == 'Microsoft-Windows-Windows Firewall with Advanced Security':
        protocol = data.get('Protocol', 'unknown')
        remote_addr = data.get('RemoteAddress', 'unknown')
        remote_port = data.get('RemotePort', 'unknown')
        action = data.get('Action', 'unknown')
        return {
            'type': 'firewall_block',
            'level': 'MEDIUM',
            'summary': f"Firewall {action} {protocol} connection from {remote_addr}:{remote_port}"
        }
    elif provider == 'Custom-SIEM-Alert' and 'suspicious network' in raw_xml:
        severity = data.get('Severity', 'MEDIUM')
        dest_ip = data.get('DestinationIp', 'unknown')
        bytes_per_sec = data.get('BytesPerSec', 'unknown')
        return {
            'type': 'suspicious_traffic',
            'level': severity,
            'summary': f"Suspicious network traffic detected to {dest_ip} ({bytes_per_sec} bytes/sec)"
        }
    return None

def windows_system_access_detector(event_data: Dict) -> Optional[Dict]:
    """Detect unauthorized system access attempts."""
    event_id = event_data.get('event_id')
    provider = event_data.get('provider', '')
    data = event_data.get('data', {})
    raw_xml = event_data.get('raw_xml', '').lower()
    
    # Critical system paths to monitor
    critical_paths = [
        'system32', 'syswow64', 'windows\\security',
        'program files', 'boot', 'drivers\\etc\\hosts',
        'windows\\system', 'sam', 'security', 'system\\config'
    ]
    
    # Map of event IDs to their security implications
    access_events = {
        '4663': 'Object access attempt',  # File system access
        '4670': 'Permissions modification',  # File system permissions modified
        '4656': 'Object access requested',  # Handle to an object requested
        '4657': 'Registry value modified',  # Registry value modified
        '4658': 'Handle to object closed',  # Handle to object closed with potential modifications
        '4660': 'Object deleted'  # Object deleted
    }
    
    if event_id in access_events:
        object_name = data.get('ObjectName', '').lower()
        user_name = data.get('SubjectUserName', 'unknown')
        access_mask = data.get('AccessMask', 'unknown')
        result = data.get('Result', '')
        
        # Check if access was to a critical path
        for path in critical_paths:
            if path in object_name:
                access_type = access_events[event_id]
                severity = 'HIGH' if 'denied' not in result.lower() else 'MEDIUM'
                return {
                    'type': 'system_access',
                    'level': severity,
                    'summary': f"{access_type} to {object_name} by {user_name}",
                    'details': {
                        'access_type': access_type,
                        'object': object_name,
                        'user': user_name,
                        'access_mask': access_mask,
                        'result': result
                    }
                }
                
    # Check for SAM database access
    elif event_id == '4656' and 'sam' in raw_xml:
        user_name = data.get('SubjectUserName', 'unknown')
        object_name = data.get('ObjectName', 'unknown')
        return {
            'type': 'system_access',
            'level': 'CRITICAL',
            'summary': f"SAM database access attempt by {user_name}",
            'details': {
                'object': object_name,
                'user': user_name
            }
        }
        
    return None

# Register all Windows event detectors
WINDOWS_EVENT_DETECTORS = [
    windows_brute_force_detector,
    windows_privilege_escalation_detector,
    windows_malware_detector,
    windows_suspicious_network_detector,
    windows_system_access_detector
]