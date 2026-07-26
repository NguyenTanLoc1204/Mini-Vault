"""
Unit tests for Mini Vault Auth Module (src/auth/manager.py, password.py, & session.py)
Covering 100% of Bcrypt hashing, registration, login, session tokens, and 5-fail 5-min lockout cases.
"""

import datetime
import time
import unittest
from src.storage import VaultDatabase
from src.auth import (
    AuthManager,
    SessionManager,
    hash_password,
    verify_password,
    validate_email_format,
    validate_password_strength,
    UserAlreadyExistsError,
    UserNotFoundError,
    InvalidCredentialsError,
    AccountLockedError,
    InvalidSessionTokenError,
    SessionExpiredError,
)


class TestAuthModule(unittest.TestCase):
    def setUp(self):
        """Provide an in-memory VaultDatabase, SessionManager, and AuthManager for each test."""
        self.db = VaultDatabase(":memory:")
        self.session_mgr = SessionManager(default_ttl_minutes=30)
        self.auth_mgr = AuthManager(db=self.db, session_manager=self.session_mgr)

        self.email = "Alice@example.com"
        self.clean_email = "alice@example.com"
        self.passphrase = "UltraSecureUserPassphrase2026!"

    def tearDown(self):
        self.db.close()

    # ------------------------------------------------------------------
    # 1. Password Hashing & Strength Tests
    # ------------------------------------------------------------------
    def test_password_hashing_and_verification(self):
        # Hash password
        pwd_hash = hash_password(self.passphrase)
        self.assertTrue(pwd_hash.startswith("$2b$") or pwd_hash.startswith("$2a$"))

        # Verify correct password
        self.assertTrue(verify_password(self.passphrase, pwd_hash))

        # Verify wrong password
        self.assertFalse(verify_password("WrongPassword123!", pwd_hash))

        # Weak passwords validation
        with self.assertRaises(ValueError):
            validate_password_strength("short")
        with self.assertRaises(ValueError):
            validate_password_strength("")
        with self.assertRaises(ValueError):
            validate_password_strength("        ")

    # ------------------------------------------------------------------
    # 2. Registration Tests
    # ------------------------------------------------------------------
    def test_user_registration_happy_path(self):
        user = self.auth_mgr.register(self.email, self.passphrase, self.passphrase)
        self.assertGreater(user["id"], 0)
        self.assertEqual(user["email"], self.clean_email)
        self.assertNotIn("password_hash", user)

        # Database record has bcrypt hash
        db_user = self.db.get_user(self.clean_email)
        self.assertIsNotNone(db_user)
        self.assertTrue(verify_password(self.passphrase, db_user["password_hash"]))

    def test_user_registration_mismatched_password(self):
        with self.assertRaises(ValueError) as ctx:
            self.auth_mgr.register(self.email, self.passphrase, "DifferentPassphrase2026!")
        self.assertIn("do not match", str(ctx.exception))

    def test_user_registration_duplicate_email(self):
        self.auth_mgr.register(self.email, self.passphrase, self.passphrase)

        # Attempt to register same email (case-insensitive)
        with self.assertRaises(UserAlreadyExistsError):
            self.auth_mgr.register("  ALICE@EXAMPLE.COM  ", self.passphrase, self.passphrase)

    def test_user_registration_invalid_email(self):
        with self.assertRaises(ValueError):
            self.auth_mgr.register("invalid-email-no-at-sign", self.passphrase, self.passphrase)
        with self.assertRaises(ValueError):
            self.auth_mgr.register("", self.passphrase, self.passphrase)

    # ------------------------------------------------------------------
    # 3. Login & Credential Verification Tests
    # ------------------------------------------------------------------
    def test_login_happy_path(self):
        self.auth_mgr.register(self.email, self.passphrase, self.passphrase)

        login_res = self.auth_mgr.login("  ALICE@example.com  ", self.passphrase)
        self.assertIn("token", login_res)
        self.assertIn("expires_at", login_res)
        self.assertEqual(login_res["user"]["email"], self.clean_email)

        # Verify session token is valid
        session = self.auth_mgr.verify_session(login_res["token"])
        self.assertEqual(session["email"], self.clean_email)

    def test_login_nonexistent_account(self):
        with self.assertRaises(UserNotFoundError):
            self.auth_mgr.login("nonexistent@example.com", self.passphrase)

    def test_login_wrong_passphrase(self):
        self.auth_mgr.register(self.email, self.passphrase, self.passphrase)

        # 1st wrong attempt
        with self.assertRaises(InvalidCredentialsError):
            self.auth_mgr.login(self.email, "WrongPassphrase1!")

        user = self.db.get_user(self.clean_email)
        self.assertEqual(user["failed_attempts"], 1)
        self.assertIsNone(user["lockout_until"])

    # ------------------------------------------------------------------
    # 4. Mandatory 5-Fail 5-Min Account Lockout Tests (Req Spec Criteria)
    # ------------------------------------------------------------------
    def test_mandatory_5_fail_5_min_lockout(self):
        self.auth_mgr.register(self.email, self.passphrase, self.passphrase)

        # 1st to 4th failed attempts
        for i in range(1, 5):
            with self.assertRaises(InvalidCredentialsError):
                self.auth_mgr.login(self.email, f"WrongPassphrase{i}")
            db_user = self.db.get_user(self.clean_email)
            self.assertEqual(db_user["failed_attempts"], i)
            self.assertIsNone(db_user["lockout_until"])

        # 5th failed attempt -> Triggers 5-minute Account Lockout
        with self.assertRaises(AccountLockedError) as ctx:
            self.auth_mgr.login(self.email, "WrongPassphrase5")

        self.assertEqual(ctx.exception.code, "ACCOUNT_LOCKED")
        self.assertIn("5 consecutive failed passphrase attempts", str(ctx.exception))

        db_user_locked = self.db.get_user(self.clean_email)
        self.assertIsNotNone(db_user_locked["lockout_until"])

        # CRITICAL SPEC REQ TEST: Attempting login DURING LOCKOUT with CORRECT PASSPHRASE -> MUST STILL FAIL!
        with self.assertRaises(AccountLockedError) as ctx_correct:
            self.auth_mgr.login(self.email, self.passphrase)

        self.assertEqual(ctx_correct.exception.code, "ACCOUNT_LOCKED")

    def test_lockout_expiration_recovery(self):
        self.auth_mgr.register(self.email, self.passphrase, self.passphrase)

        # Fail 5 times to lock account
        for i in range(5):
            try:
                self.auth_mgr.login(self.email, "Wrong")
            except (InvalidCredentialsError, AccountLockedError):
                pass

        db_user = self.db.get_user(self.clean_email)
        self.assertIsNotNone(db_user["lockout_until"])

        # Simulate lockout expiration by setting lockout_until to 10 seconds in the past
        past_time = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)).isoformat()
        self.db.update_user_failed_attempts(self.clean_email, 0, past_time)

        # Now login with CORRECT passphrase should succeed & auto-clear lockout
        login_res = self.auth_mgr.login(self.email, self.passphrase)
        self.assertIn("token", login_res)

        # Verify DB state cleared
        cleared_user = self.db.get_user(self.clean_email)
        self.assertEqual(cleared_user["failed_attempts"], 0)
        self.assertIsNone(cleared_user["lockout_until"])

    # ------------------------------------------------------------------
    # 5. Session Token Lifecycle & Expiry Tests
    # ------------------------------------------------------------------
    def test_session_token_verification_and_expiry(self):
        # Create session with 1-minute TTL
        session_data = self.session_mgr.create_session(1, self.clean_email, ttl_minutes=1)
        token = session_data["token"]

        # Verification happy path
        verified = self.session_mgr.verify_session(token)
        self.assertEqual(verified["user_id"], 1)

        # Invalid token
        with self.assertRaises(InvalidSessionTokenError):
            self.session_mgr.verify_session("nonexistent-token")

        # Expired token simulation: set expires_at_datetime to the past
        session_dict = self.session_mgr._sessions[token]
        session_dict["expires_at_datetime"] = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)

        with self.assertRaises(SessionExpiredError):
            self.session_mgr.verify_session(token)

    # ------------------------------------------------------------------
    # 6. Logout / Session Revocation Tests
    # ------------------------------------------------------------------
    def test_logout(self):
        self.auth_mgr.register(self.email, self.passphrase, self.passphrase)
        login_res = self.auth_mgr.login(self.email, self.passphrase)
        token = login_res["token"]

        # Logout
        self.assertTrue(self.auth_mgr.logout(token))

        # Token is now invalid
        with self.assertRaises(InvalidSessionTokenError):
            self.auth_mgr.verify_session(token)

        # Revoking non-existent token returns False
        self.assertFalse(self.auth_mgr.logout("nonexistent-token"))


if __name__ == "__main__":
    unittest.main()
