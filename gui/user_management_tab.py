"""
User management tab for administrators.
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                           QTableWidget, QTableWidgetItem, QDialog, QLabel,
                           QLineEdit, QComboBox, QMessageBox, QInputDialog)
from PyQt5.QtCore import Qt
import os
from database.models import User
from utils.security import hash_password

class AddUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the add user dialog UI."""
        self.setWindowTitle("Add New User")
        layout = QVBoxLayout()
        
        # Username field
        layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        layout.addWidget(self.username_input)
        
        # Password field
        layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)
        
        # Role selection
        layout.addWidget(QLabel("Role:"))
        self.role_combo = QComboBox()
        self.role_combo.addItems(["user", "admin", "analyst"])
        layout.addWidget(self.role_combo)
        
        # Buttons
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)

class UserManagementTab(QWidget):
    def __init__(self, db_session, user):
        super().__init__()
        self.db_session = db_session
        self.user = user
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user management tab UI."""
        if self.user.role != "admin":
            layout = QVBoxLayout()
            layout.addWidget(QLabel("Access Denied: Admin privileges required"))
            self.setLayout(layout)
            return
            
        layout = QVBoxLayout()
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.add_user_btn = QPushButton("Add User")
        self.add_user_btn.clicked.connect(self.add_user)
        btn_layout.addWidget(self.add_user_btn)
        
        self.refresh_btn = QPushButton("Refresh List")
        self.refresh_btn.clicked.connect(self.refresh_users)
        btn_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(btn_layout)
        
        # Users table
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(5)
        self.users_table.setHorizontalHeaderLabels([
            "User ID", "Username", "Role", "Created", "Actions"
        ])
        layout.addWidget(self.users_table)
        
        self.setLayout(layout)
        self.refresh_users()
    
    def refresh_users(self):
        """Refresh the users list."""
        self.users_table.setRowCount(0)
        users = self.db_session.query(User).all()
        
        for row, user in enumerate(users):
            self.users_table.insertRow(row)
            
            # User ID
            self.users_table.setItem(
                row, 0, 
                QTableWidgetItem(str(user.user_id))
            )
            
            # Username
            self.users_table.setItem(
                row, 1,
                QTableWidgetItem(user.username)
            )
            
            # Role
            self.users_table.setItem(
                row, 2,
                QTableWidgetItem(user.role)
            )
            
            # Created date
            self.users_table.setItem(
                row, 3,
                QTableWidgetItem(user.created_at.strftime("%Y-%m-%d %H:%M"))
            )
            
            # Action buttons
            action_widget = QWidget()
            action_layout = QHBoxLayout()
            action_layout.setContentsMargins(0, 0, 0, 0)
            
            # Reset password button
            reset_pwd_btn = QPushButton("Reset Password")
            reset_pwd_btn.clicked.connect(
                lambda checked, u=user: self.reset_password(u)
            )
            action_layout.addWidget(reset_pwd_btn)
            
            # Delete button (can't delete yourself)
            if user.user_id != self.user.user_id:
                delete_btn = QPushButton("Delete")
                delete_btn.clicked.connect(
                    lambda checked, u=user: self.delete_user(u)
                )
                action_layout.addWidget(delete_btn)
            
            action_widget.setLayout(action_layout)
            self.users_table.setCellWidget(row, 4, action_widget)
    
    def add_user(self):
        """Show dialog to add a new user."""
        dialog = AddUserDialog(self)
        if dialog.exec_():
            username = dialog.username_input.text().strip()
            password = dialog.password_input.text()
            role = dialog.role_combo.currentText()
            
            if not username or not password:
                QMessageBox.warning(self, "Error", "Username and password required")
                return
                
            try:
                # Check if username exists
                existing = self.db_session.query(User).filter_by(
                    username=username
                ).first()
                if existing:
                    QMessageBox.warning(self, "Error", "Username already exists")
                    return
                
                # Create new user
                user = User(
                    username=username,
                    password_hash=hash_password(password),
                    role=role
                )
                self.db_session.add(user)
                self.db_session.commit()
                
                self.refresh_users()
                QMessageBox.information(
                    self,
                    "Success",
                    f"User '{username}' created successfully"
                )
                
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Error",
                    f"Error creating user: {str(e)}"
                )
    
    def reset_password(self, user):
        """Reset a user's password."""
        new_password, ok = QInputDialog.getText(
            self,
            "Reset Password",
            f"Enter new password for {user.username}:",
            QLineEdit.Password
        )
        
        if ok and new_password:
            try:
                user.password_hash = hash_password(new_password)
                self.db_session.commit()
                QMessageBox.information(
                    self,
                    "Success",
                    f"Password reset for {user.username}"
                )
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Error",
                    f"Error resetting password: {str(e)}"
                )
    
    def delete_user(self, user):
        """Delete a user and all associated data."""
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete user '{user.username}'?\n\n"
            "This will also delete all associated logs, alerts, reports, "
            "and monitoring sessions for this user.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # Get all monitoring sessions for this user
                from database.models import MonitoringSession
                sessions = self.db_session.query(MonitoringSession).filter_by(
                    user_id=user.user_id
                ).all()
                
                # Delete monitoring sessions first
                for session in sessions:
                    self.db_session.delete(session)
                
                # Get all logs for this user
                from database.models import Log
                logs = self.db_session.query(Log).filter_by(
                    user_id=user.user_id
                ).all()
                
                # Delete logs and their associated alerts
                for log in logs:
                    # Alerts will be deleted automatically due to cascade
                    self.db_session.delete(log)
                
                # Get all reports for this user
                from database.models import Report
                reports = self.db_session.query(Report).filter_by(
                    user_id=user.user_id
                ).all()
                
                # Delete reports
                for report in reports:
                    # Delete the actual report file if it exists
                    if os.path.exists(report.report_path):
                        try:
                            os.remove(report.report_path)
                        except:
                            pass  # Continue even if file deletion fails
                    self.db_session.delete(report)
                
                # Finally delete the user
                self.db_session.delete(user)
                
                # Commit all changes
                self.db_session.commit()
                
                self.refresh_users()
                QMessageBox.information(
                    self,
                    "Success",
                    f"User '{user.username}' and all associated data deleted successfully"
                )
            except Exception as e:
                # Rollback in case of error
                self.db_session.rollback()
                QMessageBox.warning(
                    self,
                    "Error",
                    f"Error deleting user: {str(e)}"
                )