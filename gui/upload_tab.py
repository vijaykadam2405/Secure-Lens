"""
Upload tab for manual log file analysis.
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QFileDialog, QTextEdit, QLabel, QProgressBar, QMessageBox)
from PyQt5.QtCore import Qt
from database.models import Log, Alert, Report
from core import BaseLogParser, LogFormatDetector
from core.threat_detector import ThreatDetector
from datetime import datetime
import os
import json

class UploadTab(QWidget):
    def __init__(self, db_session, user):
        super().__init__()
        self.db_session = db_session
        self.user = user
        self.format_detector = LogFormatDetector()
        self.threat_detector = ThreatDetector()
        self.log_parser = None  # Will be initialized based on log format
        self.current_log_id = None  # Store current log ID for report generation
        self.current_threats = None  # Store current threats for report generation
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the upload tab UI elements."""
        layout = QVBoxLayout()
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Upload button
        self.upload_btn = QPushButton("Upload Log File")
        self.upload_btn.clicked.connect(self.handle_upload)
        button_layout.addWidget(self.upload_btn)
        
        # Generate Report button (initially disabled)
        self.report_btn = QPushButton("Generate Report")
        self.report_btn.clicked.connect(self.generate_report)
        self.report_btn.setEnabled(False)
        button_layout.addWidget(self.report_btn)
        
        # File info label
        self.file_label = QLabel("No file selected")
        button_layout.addWidget(self.file_label)
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results area
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def handle_upload(self):
        """Handle log file upload and analysis."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Log File",
            "",
            "Log Files (*.log *.txt);;All Files (*.*)"
        )
        
        if not file_path:
            return
            
        self.file_label.setText(os.path.basename(file_path))
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.results_text.clear()
        
        try:
            # Detect log format and initialize appropriate parser
            self.results_text.append("Detecting log format...")
            log_format = self.format_detector.detect_format(file_path)
            self.log_parser = self.format_detector.get_parser_for_format(log_format)
            
            # Parse log file
            self.results_text.append(f"Analyzing {log_format} format log file...")
            log_entries = self.log_parser.parse_file(file_path)
            
            # Store log file in database
            log = Log(
                user_id=self.user.user_id,
                file_name=os.path.basename(file_path),
                file_path=file_path,
                raw_content=open(file_path, 'r').read(),
                processed_at=datetime.now()  # Use correct field name from model
            )
            self.db_session.add(log)
            self.db_session.commit()
            
            # Store log ID for report generation
            self.current_log_id = log.log_id
            
            self.progress_bar.setValue(50)
            
            # Analyze for threats
            threats = []
            for entry in log_entries:
                threat = self.threat_detector.analyze_log_entry(entry)
                if threat:
                    # Add timestamp to threat data
                    if 'timestamp' not in threat and hasattr(entry, 'timestamp'):
                        threat['timestamp'] = entry.timestamp
                    threats.append(threat)
                    # Store alert in database
                    alert = Alert(
                        log_id=log.log_id,
                        threat_level=threat['threat_level'],
                        summary=threat['summary'],
                        timestamp=datetime.now()
                    )
                    self.db_session.add(alert)
            
            # Store threats for report generation
            self.current_threats = threats
            
            # Enable report generation button if threats were found
            self.report_btn.setEnabled(len(threats) > 0)
            
            self.db_session.commit()
            self.progress_bar.setValue(100)
            
            # Display detailed analysis results
            self.results_text.append("\n====== Analysis Results ======")
            self.results_text.append(f"\nProcessed {len(log_entries)} log entries from {os.path.basename(file_path)}")
            
            # Display parsed entries summary
            entry_types = {}
            for entry in log_entries:
                event_type = entry.get('event_type', 'unknown')
                entry_types[event_type] = entry_types.get(event_type, 0) + 1
            
            self.results_text.append("\nEvent Types Found:")
            for event_type, count in entry_types.items():
                self.results_text.append(f"- {event_type}: {count} entries")
            
            # Display threat analysis
            if threats:
                self.results_text.append("\n====== Threat Summary ======")
                
                # Group threats by severity
                threat_levels = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
                for threat in threats:
                    level = threat.get('threat_level', 'LOW')
                    threat_levels[level].append(threat)
                
                # Display summary counts
                total_threats = len(threats)
                highest_level = max(level for level, items in threat_levels.items() if items)
                self.results_text.append(f"\nTotal Threats Detected: {total_threats}")
                self.results_text.append(f"Highest Severity: {highest_level}")
                
                # Count by severity
                for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    count = len(threat_levels[level])
                    if count > 0:
                        self.results_text.append(f"{level}: {count} threat(s)")
                
                # Display detailed breakdown
                self.results_text.append("\n====== Detailed Threat Analysis ======")
                
                # Show threats by severity level
                for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    level_threats = threat_levels[level]
                    if level_threats:
                        self.results_text.append(f"\n{level} Severity Threats:")
                        
                        # Group by threat type
                        threat_types = {}
                        for threat in level_threats:
                            threat_type = threat.get('rule_name', 'Unknown')
                            if threat_type not in threat_types:
                                threat_types[threat_type] = []
                            threat_types[threat_type].append(threat)
                        
                        # Display each threat type
                        for threat_type, type_threats in threat_types.items():
                            self.results_text.append(f"\n  {threat_type} ({len(type_threats)} incidents):")
                            for threat in type_threats:
                                self.results_text.append(f"    - {threat['summary']}")
                                if 'source_ip' in threat and threat['source_ip']:
                                    self.results_text.append(f"      Source: {threat['source_ip']}")
                                if 'timestamp' in threat and threat['timestamp']:
                                    self.results_text.append(f"      Time: {threat['timestamp']}")
                                if 'details' in threat:
                                    for key, value in threat['details'].items():
                                        self.results_text.append(f"      {key.title()}: {value}")
            else:
                self.results_text.append("\nNo threats detected in the log file.")
                
            self.results_text.append("\n====== Analysis Complete ======")
                
        except Exception as e:
            self.results_text.append(f"\nError processing file: {str(e)}")
            # Disable report button on error
            self.report_btn.setEnabled(False)
        finally:
            self.progress_bar.setVisible(False)
            
    def generate_report(self):
        """Generate a PDF report for the currently analyzed log file."""
        if not self.current_threats:
            QMessageBox.warning(
                self,
                "No Data",
                "No threats detected to generate report."
            )
            return
            
        try:
            # Get the log file associated with the current threats
            log = self.db_session.query(Log).filter_by(log_id=self.current_log_id).first()
            if not log:
                raise Exception("Log file not found in database")
            
            # Create reports directory if it doesn't exist
            os.makedirs('reports', exist_ok=True)
            
            # Remove any existing JSON files
            for file in os.listdir('reports'):
                if file.endswith('.json'):
                    try:
                        os.remove(os.path.join('reports', file))
                    except:
                        pass
            
            # Create report data
            report_data = {
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'generated_by': self.user.username,
                'report_type': 'Log Upload',
                'log_file': log.file_name,
                'log_upload_time': log.processed_at.strftime('%Y-%m-%d %H:%M:%S') if log.processed_at else datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'alerts': []
            }
            
            # Group threats by severity for better organization
            threats_by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
            for threat in self.current_threats:
                threat_data = {
                    'threat_level': threat['threat_level'],
                    'summary': threat['summary'],
                    'timestamp': threat.get('timestamp', datetime.now()).strftime('%Y-%m-%d %H:%M:%S') if isinstance(threat.get('timestamp'), datetime) else threat.get('timestamp', 'N/A'),
                    'source_ip': threat.get('source_ip', 'N/A'),
                    'service': threat.get('service', 'N/A'),
                    'port': threat.get('port', 'N/A'),
                    'log_file': log.file_name
                }
                severity = threat['threat_level']
                if severity in threats_by_severity:
                    threats_by_severity[severity].append(threat_data)
                else:
                    threats_by_severity['LOW'].append(threat_data)
            
            # Add threats to report in order of severity
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                report_data['alerts'].extend(threats_by_severity[severity])
            
            # Generate unique filename for PDF
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = os.path.abspath(f"reports/security_report_{timestamp}.pdf")
            
            # Use the ReportsTab's PDF generation method
            from .reports_tab import ReportsTab
            reports_tab = ReportsTab(self.db_session, self.user)
            reports_tab.generate_pdf_report(report_path, report_data)
            
            # Create report record in database
            report = Report(
                user_id=self.user.user_id,
                report_path=report_path,
                log_id=self.current_log_id,
                created_at=datetime.now()
            )
            self.db_session.add(report)
            self.db_session.commit()
            
            QMessageBox.information(
                self,
                "Success",
                "Report generated successfully. You can view it in the Reports tab."
            )
            
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Error generating report: {str(e)}"
            )