"""
Auth Module: User Registration, Login, Bcrypt Hashing, Session Token, & 5-Fail 5-Min Lockout
"""

from src.auth.password import (
    hash_password,
    verify_password,
    validate_email_format,
    validate_password_strength,
)
from src.auth.session import (
    SessionManager,
    SessionError,
    InvalidSessionTokenError,
    SessionExpiredError,
)
from src.auth.manager import (
    AuthManager,
    AuthError,
    UserAlreadyExistsError,
    UserNotFoundError,
    InvalidCredentialsError,
    AccountLockedError,
)

__all__ = [
    "hash_password",
    "verify_password",
    "validate_email_format",
    "validate_password_strength",
    "SessionManager",
    "SessionError",
    "InvalidSessionTokenError",
    "SessionExpiredError",
    "AuthManager",
    "AuthError",
    "UserAlreadyExistsError",
    "UserNotFoundError",
    "InvalidCredentialsError",
    "AccountLockedError",
]
