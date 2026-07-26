"""
Auth Manager Module for Mini Vault: Registration, Login, Lockout Enforcement, & Sessions
"""

import datetime
import sqlite3
from typing import Dict, Optional, Tuple, Any

from src.storage import VaultDatabase
from src.auth.password import (
    hash_password,
    verify_password,
    validate_email_format,
    validate_password_strength,
)
from src.auth.session import (
    SessionManager,
    InvalidSessionTokenError,
    SessionExpiredError,
)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 5


class AuthError(Exception):
    """Base exception for authentication errors."""
    pass


class UserAlreadyExistsError(AuthError):
    """Raised when registering an email that already exists."""
    pass


class UserNotFoundError(AuthError):
    """Raised when logging in with a non-existent email address."""
    pass


class InvalidCredentialsError(AuthError):
    """Raised when passphrase verification fails."""
    pass


class AccountLockedError(AuthError):
    """Raised when attempting login on a locked-out account ('ACCOUNT_LOCKED')."""
    def __init__(self, message: str = "Account is locked due to too many failed attempts. Try again later."):
        super().__init__(message)
        self.code = "ACCOUNT_LOCKED"


class AuthManager:
    def __init__(
        self,
        db: Optional[VaultDatabase] = None,
        session_manager: Optional[SessionManager] = None,
        max_failed_attempts: int = MAX_FAILED_ATTEMPTS,
        lockout_duration_minutes: int = LOCKOUT_DURATION_MINUTES,
    ):
        self.db = db if db is not None else VaultDatabase()
        self.session_manager = (
            session_manager if session_manager is not None else SessionManager()
        )
        self.max_failed_attempts = max_failed_attempts
        self.lockout_duration_minutes = lockout_duration_minutes

    def register(
        self, email: str, passphrase: str, confirm_passphrase: str
    ) -> Dict[str, Any]:
        """
        Register a new user (Section 0.2):
        1. Validate email syntax, passphrase strength, and matching confirm_passphrase.
        2. Hash passphrase using Bcrypt.
        3. Save user to database (raises UserAlreadyExistsError if email exists).
        """
        clean_email = validate_email_format(email)

        if passphrase != confirm_passphrase:
            raise ValueError("Passphrase and confirm passphrase do not match.")

        validate_password_strength(passphrase)
        password_hash = hash_password(passphrase)

        try:
            user = self.db.create_user(clean_email, password_hash)
            return {
                "id": user["id"],
                "email": user["email"],
                "created_at": user["created_at"],
            }
        except sqlite3.IntegrityError:
            raise UserAlreadyExistsError(f"User with email '{clean_email}' already exists.")

    def _parse_iso_timestamp(self, timestamp_str: str) -> datetime.datetime:
        """Parse ISO timestamp string into timezone-aware datetime."""
        # Handle trailing 'Z' for UTC
        clean_str = timestamp_str.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt

    def check_lockout_status(self, user: Dict[str, Any]) -> Tuple[bool, Optional[int]]:
        """
        Check if account is currently locked out.
        Returns (is_locked: bool, seconds_remaining: Optional[int]).
        """
        lockout_until_str = user.get("lockout_until")
        if not lockout_until_str:
            return False, None

        now = datetime.datetime.now(datetime.timezone.utc)
        lockout_until = self._parse_iso_timestamp(lockout_until_str)

        if now < lockout_until:
            remaining = int((lockout_until - now).total_seconds())
            return True, max(remaining, 1)

        # Lockout expired
        return False, None

    def login(self, email: str, passphrase: str) -> Dict[str, Any]:
        """
        Log in a user (Section 0.2):
        1. Verify account exists.
        2. Check 5-minute Account Lockout status:
           - If locked: MUST fail immediately, even if correct passphrase is provided.
           - If lockout expired: Reset failed attempts and lockout timestamp.
        3. Verify passphrase using Bcrypt:
           - Wrong: Increment failed_attempts. If >= 5, set lockout_until = now + 5 mins.
           - Correct: Reset failed_attempts & lockout_until, issue session token.
        """
        if not email or not email.strip():
            raise UserNotFoundError("Account does not exist.")

        clean_email = email.strip().lower()
        user = self.db.get_user(clean_email)
        if not user:
            raise UserNotFoundError("Account does not exist.")

        # Check Account Lockout status
        is_locked, remaining_seconds = self.check_lockout_status(user)
        if is_locked:
            # MANDATORY SPEC REQ: Refuse login attempt even if correct passphrase provided
            raise AccountLockedError(
                f"Account is locked due to {self.max_failed_attempts} consecutive failed passphrase attempts. "
                f"Try again in {remaining_seconds} seconds."
            )

        # If previous lockout expired, clear DB lockout status
        if user.get("lockout_until") is not None and not is_locked:
            self.db.reset_user_lockout(clean_email)
            user["failed_attempts"] = 0
            user["lockout_until"] = None

        # Verify passphrase
        is_valid = verify_password(passphrase, user["password_hash"])
        now = datetime.datetime.now(datetime.timezone.utc)

        if not is_valid:
            new_failed_attempts = user["failed_attempts"] + 1

            if new_failed_attempts >= self.max_failed_attempts:
                # Trigger 5-minute account lockout
                lockout_until = now + datetime.timedelta(minutes=self.lockout_duration_minutes)
                lockout_until_iso = lockout_until.isoformat()
                self.db.update_user_failed_attempts(clean_email, 0, lockout_until_iso)
                self.db.log_audit_event(
                    requester_email=clean_email,
                    target_resource=f"user/{clean_email}",
                    action="LOGIN",
                    reason=f"ACCOUNT_LOCKED_5_FAILED_ATTEMPTS",
                )
                raise AccountLockedError(
                    f"5 consecutive failed passphrase attempts. Account locked for {self.lockout_duration_minutes} minutes."
                )

            # Record failed attempt
            self.db.update_user_failed_attempts(clean_email, new_failed_attempts, None)
            self.db.log_audit_event(
                requester_email=clean_email,
                target_resource=f"user/{clean_email}",
                action="LOGIN",
                reason=f"FAILED_PASSPHRASE_ATTEMPT_{new_failed_attempts}",
            )
            raise InvalidCredentialsError("Invalid email or passphrase.")

        # Correct Passphrase: Reset failed attempts & lockout
        self.db.reset_user_lockout(clean_email)

        # Issue Session Token (30 minutes expiry)
        session_data = self.session_manager.create_session(user["id"], user["email"])

        return {
            "token": session_data["token"],
            "expires_at": session_data["expires_at"],
            "user": {
                "id": user["id"],
                "email": user["email"],
            },
        }

    def verify_session(self, token: str) -> Dict[str, Any]:
        """Verify session token and return user identity."""
        return self.session_manager.verify_session(token)

    def logout(self, token: str) -> bool:
        """Log out user by revoking session token."""
        return self.session_manager.revoke_session(token)
