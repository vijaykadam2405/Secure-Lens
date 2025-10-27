"""
Database initialization and connection management.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base, User
import bcrypt

def create_admin_user(session):
    """Create admin user if it doesn't exist."""
    admin = session.query(User).filter_by(username='admin').first()
    if not admin:
        # Hash the password
        password = 'admin123'  # Default admin password
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        # Create admin user
        admin = User(
            username='admin',
            password_hash=password_hash.decode('utf-8'),  # Store as string
            role='admin'
        )
        session.add(admin)
        session.commit()
        print("Created admin user with default password")
    return admin

def init_database():
    """Initialize the database and create tables if they don't exist."""
    # Create SQLite database engine with thread-safe configuration
    engine = create_engine(
        'sqlite:///database/soc_copilot.db',
        connect_args={'check_same_thread': False}
    )
    
    # Create all tables
    Base.metadata.create_all(engine)
    
    # Create session factory
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # Ensure admin user exists
    create_admin_user(session)
    
    return session