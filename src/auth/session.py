"""
Session Token Manager for Mini Vault
"""

import datetime
import secrets
from typing import Dict, Optional, Any


class SessionError(Exception):
    """Base exception for Session operations."""
    pass


class InvalidSessionTokenError(SessionError):
    """Raised when a session token is invalid or missing."""
    pass


class SessionExpiredError(SessionError):
    """Raised when a session token has expired."""
    pass


class SessionManager:
    def __init__(self, default_ttl_minutes: int = 30):
        self.default_ttl_minutes = default_ttl_minutes
        # Active sessions stored in-memory: { token: session_dict }
        self._sessions: Dict[str, Dict[str, Any]] = {}

    def create_session(
        self, user_id: int, email: str, ttl_minutes: Optional[int] = None
    ) -> Dict[str, Any]:
        """Generate a cryptographically secure session token and store in memory."""
        if not user_id or user_id <= 0:
            raise ValueError("Invalid user_id for session creation.")
        if not email or not email.strip():
            raise ValueError("Invalid email for session creation.")

        clean_email = email.strip().lower()
        ttl = ttl_minutes if ttl_minutes is not None else self.default_ttl_minutes
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ttl)

        # 256-bit entropy random token
        token = secrets.token_urlsafe(32)

        session_data = {
            "token": token,
            "user_id": user_id,
            "email": clean_email,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "expires_at_datetime": expires_at,
        }

        self._sessions[token] = session_data
        return {
            "token": session_data["token"],
            "user_id": session_data["user_id"],
            "email": session_data["email"],
            "created_at": session_data["created_at"],
            "expires_at": session_data["expires_at"],
        }

    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data without raising exceptions if invalid."""
        if not token or not token.strip():
            return None
        return self._sessions.get(token.strip())

    def verify_session(self, token: str) -> Dict[str, Any]:
        """
        Verify a session token.
        Raises InvalidSessionTokenError if token is invalid or missing.
        Raises SessionExpiredError if token has expired.
        """
        if not token or not token.strip():
            raise InvalidSessionTokenError("Session token is missing or empty.")

        clean_token = token.strip()
        session = self._sessions.get(clean_token)
        if not session:
            raise InvalidSessionTokenError("Invalid session token.")

        now = datetime.datetime.now(datetime.timezone.utc)
        expires_at = session["expires_at_datetime"]

        if now >= expires_at:
            # Clean up expired session
            self._sessions.pop(clean_token, None)
            raise SessionExpiredError("Session token has expired. Please log in again.")

        return {
            "token": session["token"],
            "user_id": session["user_id"],
            "email": session["email"],
            "created_at": session["created_at"],
            "expires_at": session["expires_at"],
        }

    def revoke_session(self, token: str) -> bool:
        """Revoke / logout a session token."""
        if not token or not token.strip():
            return False
        return self._sessions.pop(token.strip(), None) is not None

    def cleanup_expired_sessions(self) -> int:
        """Remove all expired sessions from memory."""
        now = datetime.datetime.now(datetime.timezone.utc)
        expired_tokens = [
            t for t, s in self._sessions.items() if now >= s["expires_at_datetime"]
        ]
        for token in expired_tokens:
            self._sessions.pop(token, None)
        return len(expired_tokens)
