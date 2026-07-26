"""
Password Security Module for Mini Vault using Bcrypt
"""

import re
import bcrypt

# Minimum length for user passphrases
MIN_PASSWORD_LENGTH = 8


def validate_password_strength(passphrase: str) -> None:
    """Validate password strength (non-empty, minimum length, not purely whitespace)."""
    if not passphrase or not passphrase.strip():
        raise ValueError("Passphrase cannot be empty or purely whitespace.")
    if len(passphrase.strip()) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Passphrase must be at least {MIN_PASSWORD_LENGTH} characters long.")


def validate_email_format(email: str) -> str:
    """Validate email format, lowercase, and trim whitespace."""
    if not email or not email.strip():
        raise ValueError("Email address cannot be empty.")
    clean_email = email.strip().lower()
    email_regex = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    if not re.match(email_regex, clean_email):
        raise ValueError("Invalid email format.")
    return clean_email


def hash_password(passphrase: str) -> str:
    """Hash passphrase using bcrypt with salt factor 12."""
    validate_password_strength(passphrase)
    # Bcrypt truncates at 72 bytes, so encode as UTF-8
    pass_bytes = passphrase.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(pass_bytes, salt)
    return hashed_bytes.decode("utf-8")


def verify_password(passphrase: str, password_hash: str) -> bool:
    """Verify passphrase against stored bcrypt hash."""
    if not passphrase or not password_hash:
        return False
    try:
        pass_bytes = passphrase.encode("utf-8")
        hash_bytes = password_hash.encode("utf-8")
        return bcrypt.checkpw(pass_bytes, hash_bytes)
    except Exception:
        return False
