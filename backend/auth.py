"""
auth.py — Authentication layer for the secure chat backend.

WHY BCRYPT (not pbkdf2_hmac)
-----------------------------
Both bcrypt and pbkdf2_hmac are acceptable KDFs for password hashing.
We chose bcrypt because:

  1. It is purpose-built for passwords. pbkdf2 is a general KDF that
     can be used for passwords, but bcrypt's design is specifically
     optimised for the brute-force cost model of password cracking.

  2. Built-in salt. bcrypt embeds the salt in the output hash string.
     With pbkdf2 you must store salt and hash separately and handle
     their serialisation yourself — more surface area for bugs.

  3. Adaptive work factor. The `rounds` parameter can be increased
     over time as hardware improves without changing the algorithm or
     breaking existing hashes.

  4. The `bcrypt.checkpw` function uses a constant-time comparison
     internally, preventing timing side-channel attacks out of the box.

SESSION TOKENS
--------------
After successful login, the server issues a 64-character hex token
(256 bits of entropy from secrets.token_hex). This token is stored in
the sessions table with an expiry timestamp. Every subsequent request
from the client must include this token inside the AES-encrypted payload.

The token is NOT a JWT. A JWT would be verifiable without a database
lookup, but for this project we prefer the simplicity and revocability
of a server-side token table.

Author: Aakarsh Prabhu
"""

import secrets
import time

import bcrypt

import db as db_module


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

BCRYPT_ROUNDS       = 12          # work factor — increase as hardware improves
SESSION_EXPIRY_SECS = 60 * 60     # 60 minutes


# ------------------------------------------------------------------
# Password hashing
# ------------------------------------------------------------------

def hash_password(password: str) -> str:
    """
    Hash a plain-text password with bcrypt.

    Returns a bcrypt hash string that includes the embedded salt,
    suitable for storing directly in the users table.
    """
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
    ).decode("utf-8")


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """
    Constant-time verification of a password against a stored bcrypt hash.
    """
    return bcrypt.checkpw(
        provided_password.encode("utf-8"),
        stored_hash.encode("utf-8"),
    )


# ------------------------------------------------------------------
# User registration
# ------------------------------------------------------------------

def register_user(username: str, password: str) -> tuple[bool, str]:
    """
    Register a new user.

    Returns (True, "") on success, or (False, reason) on failure.
    """
    if not username or not password:
        return False, "Username and password are required"

    if db_module.get_user(username):
        return False, f"Username '{username}' is already taken"

    password_hash = hash_password(password)
    db_module.insert_user(username, password_hash)
    return True, ""


# ------------------------------------------------------------------
# Login / session management
# ------------------------------------------------------------------

def login(username: str, password: str) -> tuple[str | None, str]:
    """
    Attempt to log in.

    Returns (session_token, "") on success,
    or (None, error_message) on failure.
    """
    row = db_module.get_user(username)
    if not row:
        # Do not reveal whether the username exists.
        return None, "Invalid credentials"

    if not verify_password(row["password_hash"], password):
        return None, "Invalid credentials"

    token = secrets.token_hex(32)           # 256 bits of entropy
    expires_at = time.time() + SESSION_EXPIRY_SECS
    db_module.insert_session(token, username, expires_at)
    return token, ""


def validate_session(token: str) -> tuple[str | None, str]:
    """
    Validate a session token.

    Returns (username, "") if the token is valid and not expired,
    or (None, error_message) otherwise.
    """
    row = db_module.get_session(token)
    if not row:
        return None, "Invalid or expired session token"

    if time.time() > row["expires_at"]:
        db_module.invalidate_session(token)
        return None, "Session token has expired"

    return row["username"], ""


def logout(token: str) -> None:
    """Explicitly invalidate a session token."""
    db_module.invalidate_session(token)
