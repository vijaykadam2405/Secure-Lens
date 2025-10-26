"""
Main entry point for the Threat Alert Summarizer Bot (SOC Copilot)
Desktop application for analyzing log files and detecting security threats.
"""

from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow
from database.db_init import init_database
from database.models import User
from utils.security import hash_password
from core import BaseLogParser, LogFormatDetector
from core.threat_detector import ThreatDetector
from core.monitor import LogMonitor

def create_admin_if_not_exists(db_session):
    """Create default admin user if no users exist."""
    if db_session.query(User).count() == 0:
        admin = User(
            username="admin",
            password_hash=hash_password("admin123"),  # Default password
            role="admin"
        )
        db_session.add(admin)
        db_session.commit()

def main():
    """Initialize and launch the application."""
    app = QApplication([])
    
    # Initialize database and create session
    db_session = init_database()
    
    # Ensure admin user exists
    create_admin_if_not_exists(db_session)
    
    # Create and show main window
    window = MainWindow(db_session)
    window.show()
    
    # Set up signal handling for graceful shutdown
    import signal
    def signal_handler(signum, frame):
        """Handle shutdown signals gracefully."""
        print("\nShutting down gracefully...")
        window.close()
        db_session.close()
        app.quit()
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the application event loop
    try:
        return app.exec_()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        window.close()
        db_session.close()
        return 0

if __name__ == "__main__":
    main()