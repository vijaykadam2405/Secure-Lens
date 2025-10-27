"""
Custom notification window for real-time alerts.
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QPushButton, QFrame)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QPalette

class AlertNotification(QDialog):
    """Custom notification window for displaying alerts."""
    
    def __init__(self, threat_data, parent=None):
        """Initialize the notification window."""
        super().__init__(parent)
        
        # Window flags for a borderless window that stays on top
        self.setWindowFlags(
            Qt.Window | 
            Qt.CustomizeWindowHint | 
            Qt.WindowStaysOnTopHint |
            Qt.FramelessWindowHint
        )
        
        self.setup_ui(threat_data)
        self.setup_auto_close()
        
    def setup_ui(self, threat_data):
        """Set up the notification UI."""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Security Alert!")
        header.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: white;
            }
        """)
        layout.addWidget(header)
        
        # Separator line
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("background-color: white;")
        layout.addWidget(line)
        
        # Alert content
        content_layout = QVBoxLayout()
        
        # Severity
        severity = threat_data['threat_level']
        severity_label = QLabel(f"Severity: {severity}")
        severity_label.setStyleSheet("""
            QLabel {
                font-weight: bold;
                color: white;
            }
        """)
        content_layout.addWidget(severity_label)
        
        # Summary
        summary = threat_data['summary']
        summary_label = QLabel(summary)
        summary_label.setStyleSheet("color: white;")
        summary_label.setWordWrap(True)
        content_layout.addWidget(summary_label)
        
        # Additional details if available
        if threat_data.get('source_ip'):
            ip_label = QLabel(f"Source IP: {threat_data['source_ip']}")
            ip_label.setStyleSheet("color: white;")
            content_layout.addWidget(ip_label)
            
        layout.addLayout(content_layout)
        
        # Close button
        btn_layout = QHBoxLayout()
        close_btn = QPushButton("Dismiss")
        close_btn.clicked.connect(self.close)
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 255, 255, 0.2);
                border: 1px solid white;
                color: white;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.3);
            }
        """)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        
        # Set background color based on severity
        color = {
            'CRITICAL': QColor(139, 0, 0),  # Dark Red
            'HIGH': QColor(255, 0, 0),      # Red
            'MEDIUM': QColor(255, 140, 0),  # Orange
            'LOW': QColor(0, 0, 139)        # Dark Blue
        }.get(severity, QColor(47, 47, 47))  # Dark Gray
        
        # Set up semi-transparent background
        palette = self.palette()
        palette.setColor(QPalette.Window, color)
        self.setPalette(palette)
        self.setAutoFillBackground(True)
        
        # Set size and opacity
        self.setMinimumWidth(300)
        self.setWindowOpacity(0.9)
        
    def setup_auto_close(self, timeout=5000):  # 5 seconds
        """Set up auto-close timer."""
        QTimer.singleShot(timeout, self.close)
        
    def mousePressEvent(self, event):
        """Handle mouse press to enable dragging."""
        if event.button() == Qt.LeftButton:
            self.dragPosition = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()
            
    def mouseMoveEvent(self, event):
        """Handle window dragging."""
        if event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self.dragPosition)
            event.accept()