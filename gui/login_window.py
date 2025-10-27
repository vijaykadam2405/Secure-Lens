"""
Login window for user authentication.
"""

from PyQt5.QtWidgets import (QDialog, QLabel, QLineEdit, QPushButton, 
                           QVBoxLayout, QMessageBox)
from sqlalchemy.orm import Session
from database.models import User
from utils.security import verify_password

class LoginWindow(QDialog):
    def __init__(self, db_session: Session):
        super().__init__()
        self.db_session = db_session
        self.user = None
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the login window UI elements."""
        self.setWindowTitle("SOC Copilot - Login")
        self.setGeometry(300, 300, 300, 200)
        
        layout = QVBoxLayout()
        
        # Username input
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        
        # Password input
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.login_button)
        
        self.setLayout(layout)
    
    def handle_login(self):
        """Handle login button click."""
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter both username and password.")
            return
        
        # Query user from database
        user = self.db_session.query(User).filter(User.username == username).first()
        
        if user and verify_password(password, user.password_hash):
            self.user = user
            self.accept()  # Close dialog with success
        else:
            QMessageBox.warning(self, "Error", "Invalid username or password.")
            self.password_input.clear()