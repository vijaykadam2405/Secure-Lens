"""
Real-time monitoring tab for live log analysis.
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QTextEdit, QLabel, QFileDialog, QApplication, QCheckBox,
                           QDesktopWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from core.monitor import LogMonitor
from core import BaseLogParser, LogFormatDetector
from core.threat_detector import ThreatDetector
from database.models import Log, Alert, MonitoringSession
from gui.alert_notification import AlertNotification
import os
import re
from datetime import datetime

class MonitorThread(QThread):
    """Background thread for log monitoring."""
    alert_signal = pyqtSignal(dict)
    
    def __init__(self, file_path, db_session, user, monitoring_session_id=None):
        super().__init__()
        self.file_path = file_path
        self.db_session = db_session
        self.user = user
        self.monitoring_session_id = monitoring_session_id
        self.format_detector = LogFormatDetector()
        # Detect format and get appropriate parser
        log_format = self.format_detector.detect_format(file_path)
        self.parser = self.format_detector.get_parser_for_format(log_format)
        self.detector = ThreatDetector()
        self.monitor = None
        
    def process_log_update(self, file_path, new_content):
        """Process updated log file content."""
        # For XML logs (Windows Event Logs)
        if hasattr(self.parser, 'event_parser'):
            try:
                # Clean up and preprocess the XML content
                clean_content = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', new_content)
                
                # Extract all Event elements
                events = re.findall(r'<Event.*?</Event>', clean_content, re.DOTALL | re.IGNORECASE)
                if not events:
                    return
                
                # Create a unique temporary file
                temp_dir = os.path.join(os.path.dirname(file_path), 'temp')
                os.makedirs(temp_dir, exist_ok=True)
                temp_file = os.path.join(temp_dir, f'update_{os.getpid()}_{datetime.now().strftime("%Y%m%d%H%M%S%f")}.xml')
                
                # Write events to temporary file
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write('<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n')
                    for event in events:
                        f.write(event + '\n')
                    f.write('</Events>')
            except Exception as e:
                print(f"Error processing Windows Event XML: {str(e)}")
                return
            
            try:
                # Parse the temporary file
                entries = self.parser.parse_file(temp_file)
            except Exception as e:
                print(f"Error parsing Windows events: {str(e)}")
                entries = []
            finally:
                # Clean up
                if os.path.exists(temp_file):
                    os.remove(temp_file)
        else:
            # For non-XML logs (Linux logs)
            entries = []
            for line in new_content.splitlines():
                if not line.strip():
                    continue
                entry = self.parser.parse_line(line)
                if entry:
                    entries.append(entry)
        
        # Process all entries
        for entry in entries:
            threat = self.detector.analyze_log_entry(entry)
            if threat:
                # Store in database
                raw_content = str(entry) if hasattr(entry, '__str__') else str(entry.__dict__)
                try:
                    log = Log(
                        user_id=self.user.user_id,
                        file_name=os.path.basename(file_path),
                        file_path=file_path,
                        raw_content=raw_content,
                        monitoring_session_id=self.monitoring_session_id
                    )
                    self.db_session.add(log)
                    self.db_session.flush()
                    
                    alert = Alert(
                        log_id=log.log_id,
                        threat_level=threat['threat_level'],
                        summary=threat['summary'],
                        timestamp=datetime.now()
                    )
                    
                    # If critical or high threat, set admin notification flags
                    if threat['threat_level'] in ['CRITICAL', 'HIGH']:
                        alert.needs_admin_attention = True
                        alert.admin_notified = False
                    
                    self.db_session.add(alert)
                    self.db_session.commit()
                    
                    # Add the necessary info to threat for UI
                    threat['log_id'] = log.log_id
                    threat['timestamp'] = alert.timestamp
                    
                    # Emit signal to update UI
                    self.alert_signal.emit(threat)
                except Exception as e:
                    print(f"Error storing alert: {str(e)}")
                    self.db_session.rollback()
                
                # Emit signal to update UI
                self.alert_signal.emit(threat)
    
    def run(self):
        """Start monitoring in background thread."""
        self.monitor = LogMonitor(self.file_path, self.process_log_update)
        self.monitor.start()
        
    def stop(self):
        """Stop monitoring."""
        if self.monitor:
            self.monitor.stop()
            if self.monitoring_session_id:
                # Update monitoring session end time
                session = self.db_session.query(MonitoringSession).get(self.monitoring_session_id)
                if session:
                    session.end_time = datetime.now()
                    session.status = 'completed'
                    self.db_session.commit()

class MonitorTab(QWidget):
    def __init__(self, db_session, user):
        super().__init__()
        self.db_session = db_session
        self.user = user
        self.monitor_thread = None
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the monitoring tab UI elements."""
        layout = QVBoxLayout()
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.select_file_btn = QPushButton("Select Log File")
        self.select_file_btn.clicked.connect(self.select_file)
        btn_layout.addWidget(self.select_file_btn)
        
        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.clicked.connect(self.start_monitoring)
        self.start_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        self.generate_report_btn = QPushButton("Generate Report")
        self.generate_report_btn.clicked.connect(self.generate_monitoring_report)
        self.generate_report_btn.setEnabled(False)  # Initially disabled
        btn_layout.addWidget(self.generate_report_btn)
        
        layout.addLayout(btn_layout)
        
        # Status label
        self.status_label = QLabel("Select a log file to monitor")
        layout.addWidget(self.status_label)
        
        # Alert controls
        alert_control_layout = QHBoxLayout()
        
        self.clear_btn = QPushButton("Clear Alerts")
        self.clear_btn.clicked.connect(self.clear_alerts)
        alert_control_layout.addWidget(self.clear_btn)
        
        self.show_popup_checkbox = QCheckBox("Show Alert Popups")
        self.show_popup_checkbox.setChecked(True)
        alert_control_layout.addWidget(self.show_popup_checkbox)
        
        layout.addLayout(alert_control_layout)
        
        # Alert display
        self.alert_text = QTextEdit()
        self.alert_text.setReadOnly(True)
        self.alert_text.setStyleSheet("""
            QTextEdit {
                font-family: monospace;
                font-size: 10pt;
            }
        """)
        layout.addWidget(self.alert_text)
        
        self.setLayout(layout)
        
        # Initialize instance variables
        self.log_file = None
        self.monitoring_session = None
        self.generate_report_btn.setEnabled(False)  # Initially disabled until monitoring starts
        
    def select_file(self):
        """Select log file to monitor."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Log File",
            "",
            "Log files (*.log);;All files (*.*)"
        )
        if file_path:
            self.log_file = file_path
            self.status_label.setText(f"Selected file: {file_path}")
            self.start_btn.setEnabled(True)
    
    def start_monitoring(self):
        """Start log monitoring."""
        # Create a new monitoring session
        self.monitoring_session = MonitoringSession(
            user_id=self.user.user_id,
            file_path=self.log_file,
            start_time=datetime.now(),
            status='active'
        )
        self.db_session.add(self.monitoring_session)
        self.db_session.commit()
        
        self.monitor_thread = MonitorThread(
            self.log_file, 
            self.db_session, 
            self.user,
            self.monitoring_session.session_id
        )
        self.monitor_thread.alert_signal.connect(self.handle_alert)
        self.monitor_thread.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.generate_report_btn.setEnabled(True)
        self.select_file_btn.setEnabled(False)
        self.alert_text.append(f"Started monitoring {os.path.basename(self.log_file)}...\n")
    
    def stop_monitoring(self):
        """Stop log monitoring."""
        if self.monitor_thread:
            self.monitor_thread.stop()
            self.monitor_thread.wait()
            self.monitor_thread = None
            
        self.status_label.setText("Select a log file to monitor")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.generate_report_btn.setEnabled(True)  # Keep enabled to generate final report
        self.select_file_btn.setEnabled(True)
        self.alert_text.append("\n==== Monitoring Stopped ====\n")
    
    def clear_alerts(self):
        """Clear the alerts display."""
        self.alert_text.clear()
        self.alert_text.append("Alert display cleared.\n")
        
    def generate_monitoring_report(self):
        """Generate a PDF report for the current monitoring session."""
        try:
            if not self.monitoring_session:
                return
                
            # Query all alerts for this monitoring session
            alerts = (self.db_session.query(Alert, Log)
                     .join(Log)
                     .filter(Log.monitoring_session_id == self.monitoring_session.session_id)
                     .order_by(Alert.timestamp.desc())
                     .all())
            
            if not alerts:
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.information(
                    self,
                    "No Data",
                    "No alerts found for the current monitoring session."
                )
                return
            
            # Create report data
            report_data = {
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'generated_by': self.user.username,
                'report_type': 'Real-time Monitor',
                'log_file': os.path.basename(self.log_file),
                'monitoring_start_time': self.monitoring_session.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'log_upload_time': self.monitoring_session.start_time.strftime('%Y-%m-%d %H:%M:%S'),  # Using monitoring start time as upload time
                'alerts': []
            }
            
            # Add alerts to report data
            for alert, log in alerts:
                alert_data = {
                    'threat_level': alert.threat_level,
                    'summary': alert.summary,
                    'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'log_file': log.file_name,
                    'source_ip': None,
                    'service': None,
                    'port': None
                }
                report_data['alerts'].append(alert_data)
            
            # Create reports directory if it doesn't exist
            os.makedirs('reports', exist_ok=True)
            
            # Generate unique filename for PDF
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = os.path.abspath(f"reports/monitor_report_{timestamp}.pdf")
            
            # Use the ReportsTab's PDF generation method
            from .reports_tab import ReportsTab
            reports_tab = ReportsTab(self.db_session, self.user)
            reports_tab.generate_pdf_report(report_path, report_data)
            
            # Create report record in database
            from database.models import Report
            report = Report(
                user_id=self.user.user_id,
                report_path=report_path,
                log_id=alerts[0][1].log_id,  # Link to the first log's ID
                created_at=datetime.now()
            )
            
            try:
                self.db_session.add(report)
                self.db_session.commit()
                
                # Show success message
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.information(
                    self,
                    "Success",
                    f"Monitoring report generated successfully. You can view it in the Reports tab."
                )
            except Exception as e:
                self.db_session.rollback()
                QMessageBox.warning(
                    self,
                    "Error",
                    f"Error saving report to database: {str(e)}"
                )
            
        except Exception as e:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(
                self,
                "Error",
                f"Error generating report: {str(e)}"
            )
    
    def show_notification(self, threat):
        """Display a popup notification for the threat."""
        # Get the current desktop geometry
        desktop = QDesktopWidget().availableGeometry()
        
        # Create and show the notification
        notification = AlertNotification(threat, self)
        
        # Position notification in the bottom right corner with padding
        padding = 20
        notification_x = desktop.width() - notification.width() - padding
        notification_y = desktop.height() - notification.height() - padding
        notification.move(notification_x, notification_y)
        
        notification.show()
    
    def handle_alert(self, threat):
        """Handle new threat alert."""
        colors = {
            'CRITICAL': 'darkred',
            'HIGH': 'red',
            'MEDIUM': 'orange',
            'LOW': 'blue'
        }
        
        # Format timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get the threat color
        threat_color = colors.get(threat['threat_level'], 'black')
        
        # Initialize statistics variables
        total_threats = 0
        highest_level = 'NONE'
        threat_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        try:
            # Create a new session for querying
            from sqlalchemy.orm import sessionmaker
            from sqlalchemy import create_engine
            from database.models import Base
            
            engine = create_engine('sqlite:///database/soc_copilot.db')
            Session = sessionmaker(bind=engine)
            query_session = Session()
            
            if self.monitoring_session:
                # Get the monitoring session ID
                session_id = self.monitoring_session.session_id
                
                # Get summary statistics
                stats = (
                    query_session.query(Alert.threat_level, Log.monitoring_session_id)
                    .join(Log)
                    .filter(Log.monitoring_session_id == session_id)
                    .all()
                )
                
                # Count threats by severity
                for level, _ in stats:
                    threat_counts[level] += 1
                
                # Calculate totals
                total_threats = sum(threat_counts.values())
                highest_level = max((level for level, count in threat_counts.items() if count > 0), default='NONE')
            
            # Append the new threat to the display with color
            self.alert_text.append(f"\n→ <font color='{threat_color}'>[{timestamp}] {threat['threat_level']}: {threat['summary']}</font>")
            
            # Update status text
            status_text = (
                f"Total Threats: {total_threats} | "
                f"Highest Severity: {highest_level} | "
                f"CRITICAL: {threat_counts['CRITICAL']} | "
                f"HIGH: {threat_counts['HIGH']} | "
                f"MEDIUM: {threat_counts['MEDIUM']} | "
                f"LOW: {threat_counts['LOW']}"
            )
            self.status_label.setText(status_text)
            
            # Update threat summary in display
            self.alert_text.append(f"Total Threats Detected: {total_threats}")
            self.alert_text.append(f"Highest Severity: {highest_level}\n")
            
            # Display threat details
            threat_type = threat['summary'].split(':')[0] if ':' in threat['summary'] else 'Unknown'
            threat_details = threat['summary'].split(':', 1)[1].strip() if ':' in threat['summary'] else threat['summary']
            
            # Add any additional details if available
            if 'details' in threat:
                details_str = []
                for key, value in threat['details'].items():
                    details_str.append(f"{key}: {value}")
                if details_str:
                    threat_details += f"\n      Details: {', '.join(details_str)}"
            
            # Format the alert text with indentation and type grouping
            self.alert_text.append(f"  Type: {threat_type}")
            self.alert_text.append(f"  Details: {threat_details}")
            self.alert_text.append("  " + "-" * 40 + "\n")
            
            # Add visual separator
            self.alert_text.append("-" * 50 + "\n")
            
            # Show popup notification if enabled
            if self.show_popup_checkbox.isChecked():
                self.show_notification(threat)
                
                # Make a beep sound for critical and high threats
                if threat['threat_level'] in ['CRITICAL', 'HIGH']:
                    QApplication.beep()
            
            # Auto-scroll to the bottom
            scrollbar = self.alert_text.verticalScrollBar()
            if scrollbar:
                scrollbar.setValue(scrollbar.maximum())
                
        except Exception as e:
            print(f"Error handling alert: {str(e)}")
        finally:
            if 'query_session' in locals():
                query_session.close()