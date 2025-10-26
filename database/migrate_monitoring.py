"""Database migration script to update schema with new monitoring features."""

from sqlalchemy import (create_engine, Column, Integer, String, 
                       ForeignKey, DateTime, Boolean, Text)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Initialize SQLAlchemy base
Base = declarative_base()

def backup_database(db_path):
    """Create a backup of the existing database."""
    import shutil
    backup_path = db_path + '.backup'
    if os.path.exists(db_path):
        shutil.copy2(db_path, backup_path)
        print(f"Created backup at {backup_path}")
    return backup_path

def create_monitoring_tables(engine):
    """Create new monitoring-related tables."""
    # Import all models
    from database.models import Base, MonitoringSession
    
    # Create new tables
    Base.metadata.create_all(engine, tables=[
        MonitoringSession.__table__
    ])
    print("Created new monitoring tables")

def recreate_tables(engine):
    """Drop and recreate tables with new schema."""
    # Import all models to ensure they're registered
    from database.models import Base, User, Log, Alert, Report, MonitoringSession
    
    # Drop all tables
    Base.metadata.drop_all(engine)
    print("Dropped all existing tables")
    
    # Create all tables with new schema
    Base.metadata.create_all(engine)
    print("Created all tables with new schema")
    
    # Verify reports table has log_id column
    from sqlalchemy import inspect
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns('reports')]
    if 'log_id' not in columns:
        raise Exception("Failed to create log_id column in reports table")
    
    # Re-add admin user
    from database.db_init import create_admin_user
    Session = sessionmaker(bind=engine)
    session = Session()
    create_admin_user(session)
    session.close()
    print("Re-added admin user")

def migrate():
    """Perform database migration."""
    # Database configuration
    db_path = os.path.join('database', 'soc_copilot.db')
    db_url = f'sqlite:///{db_path}'
    
    # Create backup
    backup_path = backup_database(db_path)
    
    try:
        # Connect to database
        engine = create_engine(db_url)
        
        # Drop and recreate all tables
        recreate_tables(engine)
        
        print("Migration completed successfully!")
        
    except Exception as e:
        # Restore from backup on error
        print(f"Error during migration: {e}")
        if os.path.exists(backup_path):
            import shutil
            shutil.copy2(backup_path, db_path)
            print("Restored database from backup")
        raise
        
    finally:
        # Clean up backup
        if os.path.exists(backup_path):
            os.remove(backup_path)
            print("Removed backup file")

if __name__ == '__main__':
    migrate()