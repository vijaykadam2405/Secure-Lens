"""
Linux threat detectors.
"""

from typing import Dict, Optional
import re

"""
Linux-specific threat detectors.
"""
from typing import Dict, Optional
import re
from ..detectors import DetectorType, DetectorSeverity, BaseDetector

def linux_brute_force_detector(log_entry: Dict) -> Optional[Dict]:
    """Detect brute force attacks in Linux logs."""
    raw_message = log_entry.get('raw_message', '').lower()
    if not raw_message:
        return None
        
    brute_force_patterns = [
        r'failed password',
        r'authentication failure',
        r'failed login',
        r'invalid user',
        r'failed auth',
        r'authentication failed',
        r'maximum authentication attempts exceeded'
    ]
    
    if any(re.search(pattern, raw_message) for pattern in brute_force_patterns):
        # Extract IP address if available
        ip_addresses = log_entry.get('ip_addresses', [])
        source_ip = ip_addresses[0] if ip_addresses else 'unknown'
        
        return BaseDetector.create_threat(
            type_name=DetectorType.BRUTE_FORCE,
            level=DetectorSeverity.HIGH,
            summary=f"Failed login attempt from {source_ip}",
            source=source_ip
        )
    return None

def linux_privilege_escalation_detector(log_entry: Dict) -> Optional[Dict]:
    """Detect privilege escalation attempts in Linux logs."""
    raw_message = log_entry.get('raw_message', '').lower()
    if not raw_message:
        return None
        
    priv_esc_patterns = [
        r'sudo:.*command not allowed',
        r'sudo:.*user NOT in sudoers',
        r'sudo:.*incorrect password',
        r'failed su for root',
        r'authentication failure.*su',
        r'pam_unix\(su:auth\):.*authentication failure',
        r'usermod.*root',
        r'chmod.*777',
        r'chown.*root'
    ]
    
    if any(re.search(pattern, raw_message) for pattern in priv_esc_patterns):
        # Try to extract username
        username_match = re.search(r'user[=\s]([^\s;]+)', raw_message)
        username = username_match.group(1) if username_match else 'unknown'
        
        return {
            'type': 'privilege_escalation',
            'level': 'HIGH',
            'summary': f"Privilege escalation attempt by user {username}"
        }
    return None

def linux_malware_detector(log_entry: Dict) -> Optional[Dict]:
    """Detect potential malware activity in Linux logs."""
    raw_message = log_entry.get('raw_message', '').lower()
    if not raw_message:
        return None
        
    suspicious_patterns = [
        r'reverse shell',
        r'netcat|nc -[e|l]',
        r'wget.*\.sh',
        r'curl.*\.sh',
        r'base64 -d',
        r'python.*import.*socket',
        r'bash -i',
        r'perl -e',
        r'/dev/tcp/',
        r'backdoor',
        r'trojan',
        r'malware',
        r'exploit'
    ]
    
    if any(re.search(pattern, raw_message) for pattern in suspicious_patterns):
        return {
            'type': 'malware',
            'level': 'CRITICAL',
            'summary': "Potential malware activity detected"
        }
    return None

def linux_system_access_detector(log_entry: Dict) -> Optional[Dict]:
    """Detect unauthorized system access attempts in Linux logs."""
    raw_message = log_entry.get('raw_message', '').lower()
    if not raw_message:
        return None
        
    sensitive_paths = [
        r'/etc/passwd',
        r'/etc/shadow',
        r'/etc/sudoers',
        r'/root/.*',
        r'/var/log',
        r'/etc/(ssh|ssl)',
        r'/boot/.*'
    ]
    
    for path in sensitive_paths:
        if re.search(path, raw_message):
            return {
                'type': 'system_access',
                'level': 'HIGH',
                'summary': f"Unauthorized access attempt to sensitive file"
            }
    return None

def linux_network_threat_detector(log_entry: Dict) -> Optional[Dict]:
    """Detect network-based threats in Linux logs."""
    raw_message = log_entry.get('raw_message', '').lower()
    if not raw_message:
        return None
        
    network_patterns = [
        r'port scan',
        r'nmap',
        r'multiple connection attempts',
        r'blocked by firewall',
        r'possible syn flood',
        r'dos attack',
        r'ddos'
    ]
    
    if any(re.search(pattern, raw_message) for pattern in network_patterns):
        # Extract IP address if available
        ip_addresses = log_entry.get('ip_addresses', [])
        source_ip = ip_addresses[0] if ip_addresses else 'unknown'
        
        return {
            'type': 'network_threat',
            'level': 'HIGH',
            'summary': f"Network-based attack detected from {source_ip}"
        }
    return None

def linux_file_integrity_detector(log_entry: Dict) -> Optional[Dict]:
    """Detect file integrity violations in Linux logs."""
    raw_message = log_entry.get('raw_message', '').lower()
    if not raw_message:
        return None
        
    integrity_patterns = [
        r'checksum mismatch',
        r'modified file',
        r'file corruption',
        r'integrity check failed',
        r'unauthorized modification'
    ]
    
    if any(re.search(pattern, raw_message) for pattern in integrity_patterns):
        return {
            'type': 'file_integrity',
            'level': 'HIGH',
            'summary': "File integrity violation detected"
        }
    return None

# List of all Linux detectors
LINUX_DETECTORS = [
    linux_brute_force_detector,
    linux_privilege_escalation_detector,
    linux_malware_detector,
    linux_system_access_detector,
    linux_network_threat_detector,
    linux_file_integrity_detector
]