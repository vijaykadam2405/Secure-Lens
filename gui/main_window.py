"""
Main window of the SOC Copilot application.
"""

from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                           QMessageBox)
from .login_window import LoginWindow
from database.models import User

class MainWindow(QMainWindow):
    def __init__(self, db_session):
        super().__init__()
        self.db_session = db_session
        self.user = None
        
        # Show login window first
        if not self.show_login():
            # If login was cancelled or failed, close the application
            self.close()
            return
            
        self.setup_ui()
        
    def show_login(self):
        """Show login dialog and return True if login successful."""
        login = LoginWindow(self.db_session)
        if login.exec_():
            self.user = login.user
            return True
        return False
        
    def setup_ui(self):
        """Set up the main window UI."""
        self.setWindowTitle(f"SOC Copilot - Logged in as {self.user.username}")
        self.setGeometry(100, 100, 800, 600)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Add tabs based on user role
        self.setup_tabs()
    
    def setup_tabs(self):
        """Setup the main tabs of the application."""
        from .upload_tab import UploadTab
        from .monitor_tab import MonitorTab
        from .reports_tab import ReportsTab
        
        # Add standard tabs
        self.tabs.addTab(UploadTab(self.db_session, self.user), "Upload Logs")
        self.tabs.addTab(MonitorTab(self.db_session, self.user), "Real-time Monitor")
        self.tabs.addTab(ReportsTab(self.db_session, self.user), "Reports")
        
        # Add admin-only tab if user is admin
        if self.user.role == "admin":
            from .user_management_tab import UserManagementTab
            self.tabs.addTab(UserManagementTab(self.db_session, self.user), "User Management")