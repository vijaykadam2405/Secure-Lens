"""
Reports tab for generating and viewing threat reports.
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QTableWidget, QTableWidgetItem, QMessageBox,
                           QFileDialog, QComboBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.units import inch
from database.models import Alert, Report, Log
from datetime import datetime
import os
import json

class ReportsTab(QWidget):
    def __init__(self, db_session, user):
        super().__init__()
        self.db_session = db_session
        self.user = user
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the reports tab UI elements."""
        layout = QVBoxLayout()
        
        # Top action buttons (Generate, Refresh)
        top_actions = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_reports)
        top_actions.addWidget(refresh_btn)
        top_actions.addStretch()
        layout.addLayout(top_actions)
        
        # Reports table
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(7)  # Added one more column for delete
        self.reports_table.setHorizontalHeaderLabels([
            "Report ID", "Date", "Time", "Report Type", "Threats", "Download", "Delete"
        ])
        # Set column widths
        self.reports_table.setColumnWidth(0, 100)  # Report ID
        self.reports_table.setColumnWidth(1, 100)  # Date
        self.reports_table.setColumnWidth(2, 100)  # Time
        self.reports_table.setColumnWidth(3, 150)  # Report Type
        self.reports_table.setColumnWidth(4, 80)   # Threats
        self.reports_table.setColumnWidth(5, 100)  # Download
        self.reports_table.setColumnWidth(6, 100)  # Delete
        
        layout.addWidget(self.reports_table)
        
        self.setLayout(layout)
        self.refresh_reports()
        
    def refresh_reports(self):
        """Refresh the reports list."""
        self.reports_table.setRowCount(0)
        
        # Query reports
        if self.user.role == 'admin':
            reports = self.db_session.query(Report).all()
        else:
            reports = self.db_session.query(Report).filter_by(
                user_id=self.user.user_id
            ).all()
        
        for row, report in enumerate(reports):
            self.reports_table.insertRow(row)
            
            # Report ID (make bold to emphasize uniqueness)
            id_item = QTableWidgetItem(str(report.report_id))
            id_item.setFont(QFont("Arial", 9, QFont.Bold))
            self.reports_table.setItem(row, 0, id_item)
            
            # Date
            self.reports_table.setItem(
                row, 1,
                QTableWidgetItem(report.created_at.strftime("%Y-%m-%d"))
            )
            
            # Time
            self.reports_table.setItem(
                row, 2,
                QTableWidgetItem(report.created_at.strftime("%H:%M:%S"))
            )
            
            # Report Type
            report_type = self.determine_report_type(report.report_path)
            type_item = QTableWidgetItem(report_type)
            type_item.setTextAlignment(Qt.AlignCenter)
            self.reports_table.setItem(row, 3, type_item)
            
            # Number of threats
            threats = self.count_threats_in_report(report.report_path)
            self.reports_table.setItem(
                row, 4,
                QTableWidgetItem(str(threats))
            )
            
            # Download button
            download_btn = QPushButton("Download")
            download_btn.clicked.connect(lambda checked, r=report: self.download_report(r))
            self.reports_table.setCellWidget(row, 5, download_btn)
            
            # Delete button
            delete_btn = QPushButton("Delete")
            delete_btn.clicked.connect(lambda checked, r=report: self.delete_report(r))
            delete_btn.setStyleSheet("QPushButton { color: red; }")
            self.reports_table.setCellWidget(row, 6, delete_btn)
    
    def generate_report(self):
        """Generate a new threat report."""
        try:
            # Get the most recent log file
            latest_log = self.db_session.query(Log).order_by(Log.created_at.desc()).first()
            
            if not latest_log:
                QMessageBox.information(
                    self,
                    "No Data",
                    "No logs found to generate report."
                )
                return
                
            # Query alerts only for the most recent log file
            alerts = self.db_session.query(Alert, Log).join(Log).filter(
                Log.log_id == latest_log.log_id
            ).order_by(Alert.timestamp.desc()).all()
            
            if not alerts:
                QMessageBox.information(
                    self,
                    "No Data",
                    "No alerts found for the most recent log file."
                )
                return
            
            # Create report data specifically for PDF
            report_data = {
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'generated_by': self.user.username,
                'log_file': latest_log.file_name,
                'log_upload_time': latest_log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'alerts': [],
                'report_type': "Real-time Monitor" if latest_log.monitoring_session_id else "Log Upload",
                'total_alerts': len(alerts)
            }
            
            for alert, log in alerts:
                alert_data = {
                    'threat_level': alert.threat_level,
                    'summary': alert.summary,
                    'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S') if alert.timestamp else 'N/A',
                    'log_file': log.file_name,
                    'source_ip': None,
                    'service': None,
                    'port': None,
                    'needs_admin_attention': alert.needs_admin_attention
                }
                
                # Try to extract additional info from raw log
                try:
                    from core import LogFormatDetector
                    detector = LogFormatDetector()
                    log_format = detector.detect_format(log.file_path)
                    parser = detector.get_parser_for_format(log_format)
                    
                    if parser:
                        parsed = parser.parse_line(log.raw_content)
                        if parsed:
                            if hasattr(parsed, 'ip_addresses') and parsed.ip_addresses:
                                alert_data['source_ip'] = parsed.ip_addresses[0]
                            if hasattr(parsed, 'service'):
                                alert_data['service'] = parsed.service
                            if hasattr(parsed, 'port'):
                                alert_data['port'] = parsed.port
                except:
                    pass
                
                report_data['alerts'].append(alert_data)
            
            # Create directory for reports if it doesn't exist
            os.makedirs('reports', exist_ok=True)
            
            # Generate report filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = os.path.abspath(f"reports/security_report_{timestamp}.pdf")
            
            # Generate PDF report
            self.generate_pdf_report(report_path, report_data)
            
            # Create report record with explicit log relationship
            report = Report(
                user_id=self.user.user_id,
                report_path=report_path,
                log_id=latest_log.log_id,  # Link to the log file
                log=latest_log  # Explicitly set the log relationship
            )
            
            # Add and commit to database
            self.db_session.add(report)
            self.db_session.commit()
            
            # Delete any JSON files in reports directory
            for file in os.listdir('reports'):
                if file.endswith('.json'):
                    try:
                        os.remove(os.path.join('reports', file))
                    except:
                        pass
            
            self.refresh_reports()
            
            QMessageBox.information(
                self,
                "Success",
                f"Report generated successfully: {report_path}"
            )
            
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Error generating report: {str(e)}"
            )
    
    def view_report(self, report):
        """View a generated report."""
        try:
            # Open the PDF file with the default system application
            os.startfile(report.report_path)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Error viewing report: {str(e)}"
            )
    
    def generate_pdf_report(self, report_path: str, report_data: dict):
        """Generate a PDF report."""
        doc = SimpleDocTemplate(report_path, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        elements.append(Paragraph("Security Alert Report", title_style))
        
        # Report metadata
        meta_style = ParagraphStyle(
            'MetaData',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=6
        )
        elements.append(Paragraph(f"Generated by: {report_data['generated_by']}", meta_style))
        elements.append(Paragraph(f"Generated at: {report_data['generated_at']}", meta_style))
        elements.append(Paragraph(f"Log File: {report_data['log_file']}", meta_style))
        elements.append(Paragraph(f"Log Upload Time: {report_data['log_upload_time']}", meta_style))
        elements.append(Paragraph("<br/>", styles['Normal']))
        
        # Summary section
        summary_style = ParagraphStyle(
            'Summary',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12
        )
        elements.append(Paragraph("Alert Summary", summary_style))
        
        # Count alerts by severity
        severity_counts = {}
        for alert in report_data['alerts']:
            level = alert['threat_level']
            severity_counts[level] = severity_counts.get(level, 0) + 1
        
        summary_items = []
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if level in severity_counts:
                summary_items.append(f"{level}: {severity_counts[level]}")
        
        elements.append(Paragraph(
            "Total Alerts by Severity:<br/>" + "<br/>".join(summary_items),
            styles['Normal']
        ))
        elements.append(Paragraph("<br/>", styles['Normal']))
        
        # Alerts table
        if report_data['alerts']:
            elements.append(Paragraph("Detailed Alerts", summary_style))
            table_data = [['Severity', 'Time', 'Source', 'Summary', 'File']]
            
            def format_cell(text):
                return Paragraph(str(text), styles['Normal'])
            
            for alert in report_data['alerts']:
                source = alert.get('source_ip', 'N/A')
                if alert.get('port'):
                    source += f":{alert['port']}"
                if alert.get('service'):
                    source += f" ({alert['service']})"
                
                table_data.append([
                    format_cell(alert['threat_level']),
                    format_cell(alert['timestamp']),
                    format_cell(source),
                    format_cell(alert['summary']),
                    format_cell(alert['log_file'])
                ])
            
            # Calculate column widths based on content
            table = Table(table_data, colWidths=[1*inch, 1.2*inch, 1.3*inch, 2.5*inch, 1*inch])
            # Style the table
            style = [
                # Header formatting
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                
                # Row formatting
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                
                # Grid
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
                ('LINEBELOW', (0, 0), (-1, 0), 2, colors.HexColor('#2C3E50')),
                
                # Specific column alignments
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),  # Severity
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),  # Time
            ]
            
            # Add severity-based row coloring
            for row in range(1, len(table_data)):
                severity = table_data[row][0].text
                if severity == 'CRITICAL':
                    style.append(('BACKGROUND', (0, row), (0, row), colors.HexColor('#FFEBEE')))
                elif severity == 'HIGH':
                    style.append(('BACKGROUND', (0, row), (0, row), colors.HexColor('#FFF3E0')))
            
            table.setStyle(TableStyle(style))
            elements.append(table)
        
        doc.build(elements)
    
    def determine_report_type(self, report_path):
        """Determine if the report is from upload or real-time monitoring."""
        try:
            # Query the database to get the report record and associated log
            report = self.db_session.query(Report).filter_by(report_path=report_path).first()
            if report:
                log = self.db_session.query(Log).filter_by(log_id=report.log_id).first()
                if log and log.monitoring_session_id:
                    return "Real-time Monitor"
                return "Log Upload"
        except:
            pass
        return "Unknown"
    
    def download_report(self, report):
        """Download the report to user's chosen location."""
        try:
            # Get the file extension
            _, ext = os.path.splitext(report.report_path)
            
            # Ask user for save location
            save_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Report",
                f"report_{report.report_id}{ext}",
                f"Report Files (*{ext})"
            )
            
            if save_path:
                # Copy the file to the new location
                import shutil
                shutil.copy2(report.report_path, save_path)
                
                QMessageBox.information(
                    self,
                    "Success",
                    "Report downloaded successfully!"
                )
                
                # Open the folder containing the downloaded file
                os.startfile(os.path.dirname(save_path))
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Error downloading report: {str(e)}"
            )
    
    def delete_report(self, report):
        """Delete a report from both filesystem and database."""
        try:
            # Ask for confirmation
            reply = QMessageBox.question(
                self,
                'Confirm Delete',
                f'Are you sure you want to delete report {report.report_id}?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Delete the physical file
                if os.path.exists(report.report_path):
                    os.remove(report.report_path)
                
                # Delete from database
                self.db_session.delete(report)
                self.db_session.commit()
                
                # Refresh the table
                self.refresh_reports()
                
                QMessageBox.information(
                    self,
                    "Success",
                    "Report deleted successfully!"
                )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Error deleting report: {str(e)}"
            )
            
    def count_threats_in_report(self, report_path):
        """Count the number of threats in a report."""
        try:
            # Query the database to get the report record
            report = self.db_session.query(Report).filter_by(report_path=report_path).first()
            if report and report.log_id:
                # Count alerts associated with this report's log
                alert_count = self.db_session.query(Alert).join(Log).filter(
                    Log.log_id == report.log_id
                ).count()
                return alert_count
            else:
                # If report exists but no log_id, try to parse the PDF
                import re
                from reportlab.pdfbase import pdfparser
                try:
                    with open(report_path, 'rb') as pdf_file:
                        content = pdf_file.read().decode('utf-8', errors='ignore')
                        # Look for the threat count in the content
                        match = re.search(r'Total Alerts by Severity:(.*?)CRITICAL: (\d+).*?HIGH: (\d+).*?MEDIUM: (\d+).*?LOW: (\d+)', 
                                        content, re.DOTALL)
                        if match:
                            return sum(int(x) for x in match.groups()[1:])
                except:
                    pass
        except:
            pass
        return 0