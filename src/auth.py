import bcrypt
import secrets
import time

def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt. Bcrypt automatically handles salt generation
    and stores the salt alongside the hash in the resulting bytes.
    """
    # Use a work factor (rounds) of 12 as a secure baseline
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(stored_hash: bytes, provided_password: str) -> bool:
    """
    Verifies a provided password against a stored bcrypt hash.
    """
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hash)

def generate_session_token() -> str:
    """
    Generates a secure, random 32-byte (64 character hex) session token.
    """
    return secrets.token_hex(32)

def is_token_expired(created_timestamp: float, expiry_minutes: int = 60) -> bool:
    """
    Checks if a session token has expired.
    """
    current_time = time.time()
    expiry_seconds = expiry_minutes * 60
    return (current_time - created_timestamp) > expiry_seconds
