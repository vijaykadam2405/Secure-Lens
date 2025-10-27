"""Models for the database."""

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = 'users'
    
    VALID_ROLES = {'admin', 'user', 'analyst'}
    
    user_id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    logs = relationship('Log', back_populates='user')
    reports = relationship('Report', back_populates='user')
    monitoring_sessions = relationship('MonitoringSession', back_populates='user')
    
    def __init__(self, **kwargs):
        """Initialize user with role validation."""
        if 'role' in kwargs and kwargs['role'] not in self.VALID_ROLES:
            raise ValueError(f"Invalid role. Must be one of: {', '.join(self.VALID_ROLES)}")
        super().__init__(**kwargs)

class Log(Base):
    """Log file entries model."""
    __tablename__ = 'logs'
    
    log_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_path = Column(String(1024), nullable=False)
    raw_content = Column(Text, nullable=False)
    processed_at = Column(DateTime, default=datetime.utcnow)
    monitoring_session_id = Column(Integer, ForeignKey('monitoring_sessions.session_id'), nullable=True)
    
    # Relationships
    user = relationship('User', back_populates='logs')
    alerts = relationship('Alert', back_populates='log', cascade='all, delete-orphan')
    monitoring_session = relationship('MonitoringSession', back_populates='logs')

class Alert(Base):
    """Security alerts model."""
    __tablename__ = 'alerts'
    
    alert_id = Column(Integer, primary_key=True)
    log_id = Column(Integer, ForeignKey('logs.log_id'), nullable=False)
    threat_level = Column(String(20), nullable=False)
    summary = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    needs_admin_attention = Column(Boolean, default=False)
    admin_notified = Column(Boolean, default=False)
    reviewed = Column(Boolean, default=False)
    reviewed_by = Column(Integer, ForeignKey('users.user_id'), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    
    # Relationships
    log = relationship('Log', back_populates='alerts')
    reviewer = relationship('User', foreign_keys=[reviewed_by])

class Report(Base):
    """Generated reports model."""
    __tablename__ = 'reports'
    
    report_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    report_path = Column(String(1024), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    log_id = Column(Integer, ForeignKey('logs.log_id'), nullable=True)
    
    # Relationships
    user = relationship('User', back_populates='reports')
    log = relationship('Log')

class MonitoringSession(Base):
    """Model for tracking log monitoring sessions."""
    __tablename__ = 'monitoring_sessions'
    
    session_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    file_path = Column(String(1024), nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=True)
    status = Column(String(20), nullable=False)  # 'active', 'completed', 'error'
    error_message = Column(Text, nullable=True)
    
    # Relationships
    user = relationship('User', back_populates='monitoring_sessions')
    logs = relationship('Log', back_populates='monitoring_session')