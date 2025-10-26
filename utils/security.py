"""
Security utilities for password hashing and verification.
"""

import bcrypt
from typing import Tuple

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: The plain text password to hash
        
    Returns:
        str: The hashed password as a string
    """
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    # Convert bytes to string for storage
    return hashed.decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: The plain text password to check
        hashed_password: The hashed password to check against (stored as string)
        
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        # Convert password to bytes and compare
        return bcrypt.checkpw(
            password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        # If there's any error in verification, return False
        return False