"""
Common detector types and interfaces.
"""
from typing import Dict, Optional, List, Callable

# Type alias for detector functions
DetectorFunc = Callable[[Dict], Optional[Dict]]

class DetectorType:
    """Base class defining detector types."""
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE = "malware"
    SYSTEM_ACCESS = "system_access"
    NETWORK_THREAT = "network_threat"
    FILE_INTEGRITY = "file_integrity"
    FIREWALL = "firewall"
    SUSPICIOUS_COMMAND = "suspicious_command"
    UNAUTHORIZED_ACCESS = "unauthorized_access"

class DetectorSeverity:
    """Severity levels for detected threats."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class BaseDetector:
    """Base class for implementing detectors."""
    
    @staticmethod
    def create_threat(
        type_name: str,
        level: str,
        summary: str,
        source: str = None,
        details: Dict = None
    ) -> Dict:
        """Create a standardized threat detection response."""
        threat = {
            'type': type_name,
            'level': level,
            'summary': summary
        }
        
        if source:
            threat['source'] = source
            
        if details:
            threat['details'] = details
            
        return threat