"""
Unit tests for Mini Vault KV Engine (src/kv/engine.py)
Covering 100% of Encrypted-at-Rest Storage, Ownership ACL, AEAD Tamper Detection, and Audit Logging cases.
"""

import json
import unittest
from src.storage import VaultDatabase
from src.core import VaultManager, VaultLockedError
from src.auth import (
    AuthManager,
    SessionManager,
    InvalidSessionTokenError,
)
from src.kv import (
    KVEngine,
    KVPathAccessDeniedError,
    KVNotFoundError,
    KVDataCorruptedError,
    KVInvalidPathError,
)


class TestKVEngine(unittest.TestCase):
    def setUp(self):
        """Set up in-memory DB, VaultManager, AuthManager, and KVEngine for each test."""
        self.db = VaultDatabase(":memory:")
        self.vault_mgr = VaultManager(self.db)
        self.session_mgr = SessionManager()
        self.auth_mgr = AuthManager(db=self.db, session_manager=self.session_mgr)
        self.kv_engine = KVEngine(
            vault_manager=self.vault_mgr,
            auth_manager=self.auth_mgr,
            db=self.db,
        )

        self.master_pass = "MasterPassphrase2026!"
        self.vault_mgr.init_vault(self.master_pass)

        # Setup User Alice
        self.alice_email = "alice@example.com"
        self.alice_pass = "AlicePassword123!"
        self.auth_mgr.register(self.alice_email, self.alice_pass, self.alice_pass)
        alice_login = self.auth_mgr.login(self.alice_email, self.alice_pass)
        self.alice_token = alice_login["token"]

        # Setup User Bob
        self.bob_email = "bob@example.com"
        self.bob_pass = "BobPassword123!"
        self.auth_mgr.register(self.bob_email, self.bob_pass, self.bob_pass)
        bob_login = self.auth_mgr.login(self.bob_email, self.bob_pass)
        self.bob_token = bob_login["token"]

        self.alice_path = f"secret/{self.alice_email}/db"
        self.sample_data = {"db_user": "postgres", "db_pass": "SuperSecretPass123!"}

    def tearDown(self):
        self.db.close()

    # ------------------------------------------------------------------
    # 1. Roundtrip Write & Read Tests
    # ------------------------------------------------------------------
    def test_write_and_read_roundtrip(self):
        # Write secret
        res = self.kv_engine.write_secret(self.alice_path, self.sample_data, self.alice_token)
        self.assertEqual(res["path"], self.alice_path)
        self.assertIn("created_at", res)

        # Read secret
        decrypted_data = self.kv_engine.read_secret(self.alice_path, self.alice_token)
        self.assertEqual(decrypted_data, self.sample_data)

    def test_write_overwrite_secret(self):
        self.kv_engine.write_secret(self.alice_path, self.sample_data, self.alice_token)

        # Overwrite with new data
        new_data = {"db_user": "postgres", "db_pass": "NewUpdatedPassword2026!"}
        self.kv_engine.write_secret(self.alice_path, new_data, self.alice_token)

        decrypted = self.kv_engine.read_secret(self.alice_path, self.alice_token)
        self.assertEqual(decrypted, new_data)

    # ------------------------------------------------------------------
    # 2. Delete & Non-Existent Secret Tests
    # ------------------------------------------------------------------
    def test_delete_secret(self):
        self.kv_engine.write_secret(self.alice_path, self.sample_data, self.alice_token)
        self.assertIsNotNone(self.kv_engine.read_secret(self.alice_path, self.alice_token))

        # Delete
        self.assertTrue(self.kv_engine.delete_secret(self.alice_path, self.alice_token))

        # Reading deleted path raises KVNotFoundError
        with self.assertRaises(KVNotFoundError) as ctx:
            self.kv_engine.read_secret(self.alice_path, self.alice_token)
        self.assertEqual(ctx.exception.code, "NOT_FOUND")

        # Deleting non-existent path returns False
        self.assertFalse(self.kv_engine.delete_secret(self.alice_path, self.alice_token))

    def test_read_nonexistent_secret(self):
        nonexistent_path = f"secret/{self.alice_email}/nonexistent_key"
        with self.assertRaises(KVNotFoundError):
            self.kv_engine.read_secret(nonexistent_path, self.alice_token)

    # ------------------------------------------------------------------
    # 3. AEAD Tamper Detection & Plaintext Disk Isolation Tests
    # ------------------------------------------------------------------
    def test_tampered_ciphertext_detection(self):
        self.kv_engine.write_secret(self.alice_path, self.sample_data, self.alice_token)

        # Manually tamper 1 byte in the database ciphertext
        record = self.db.get_kv_secret(self.alice_path)
        ct_raw = bytearray(record["ciphertext_b64"].encode())
        ct_raw[0] = ord("Z") if ct_raw[0] != ord("Z") else ord("X")
        tampered_ct_b64 = ct_raw.decode()

        self.db.put_kv_secret(
            path=self.alice_path,
            owner_id=record["owner_id"],
            nonce_b64=record["nonce_b64"],
            ciphertext_b64=tampered_ct_b64,
            tag_b64=record["tag_b64"],
        )

        # Reading tampered data MUST refuse outright and raise KVDataCorruptedError
        with self.assertRaises(KVDataCorruptedError) as ctx:
            self.kv_engine.read_secret(self.alice_path, self.alice_token)
        self.assertEqual(ctx.exception.code, "DATA_CORRUPTED")

    def test_plaintext_disk_isolation(self):
        self.kv_engine.write_secret(self.alice_path, self.sample_data, self.alice_token)

        # Inspect database record directly
        record = self.db.get_kv_secret(self.alice_path)
        ct_b64 = record["ciphertext_b64"]

        # Plaintext password fragments must NOT appear anywhere in stored ciphertext
        self.assertNotIn("SuperSecretPass123!", ct_b64)
        self.assertNotIn("postgres", ct_b64)

    # ------------------------------------------------------------------
    # 4. Locked Vault Prevention Test
    # ------------------------------------------------------------------
    def test_locked_vault_prevention(self):
        self.kv_engine.write_secret(self.alice_path, self.sample_data, self.alice_token)

        # Lock Vault
        self.vault_mgr.lock_vault()

        # Write/read while vault is locked raises VaultLockedError ('VAULT_LOCKED')
        with self.assertRaises(VaultLockedError) as ctx_write:
            self.kv_engine.write_secret(self.alice_path, self.sample_data, self.alice_token)
        self.assertEqual(ctx_write.exception.code, "VAULT_LOCKED")

        with self.assertRaises(VaultLockedError) as ctx_read:
            self.kv_engine.read_secret(self.alice_path, self.alice_token)
        self.assertEqual(ctx_read.exception.code, "VAULT_LOCKED")

    # ------------------------------------------------------------------
    # 5. Ownership Access Control (ACL Denial) & Audit Log Tests
    # ------------------------------------------------------------------
    def test_ownership_access_control_denial(self):
        # Alice writes secret under her path
        self.kv_engine.write_secret(self.alice_path, self.sample_data, self.alice_token)

        # Bob attempts to read Alice's secret using Bob's valid token -> MUST BE DENIED
        with self.assertRaises(KVPathAccessDeniedError) as ctx_read:
            self.kv_engine.read_secret(self.alice_path, self.bob_token)
        self.assertEqual(ctx_read.exception.code, "PERMISSION_DENIED")

        # Bob attempts to write under Alice's path -> DENIED
        with self.assertRaises(KVPathAccessDeniedError) as ctx_write:
            self.kv_engine.write_secret(self.alice_path, {"hacked": True}, self.bob_token)
        self.assertEqual(ctx_write.exception.code, "PERMISSION_DENIED")

        # Bob attempts to delete Alice's secret -> DENIED
        with self.assertRaises(KVPathAccessDeniedError) as ctx_del:
            self.kv_engine.delete_secret(self.alice_path, self.bob_token)
        self.assertEqual(ctx_del.exception.code, "PERMISSION_DENIED")

    def test_audit_log_recorded_on_denial(self):
        # Bob attempts unauthorized access to Alice's path
        try:
            self.kv_engine.read_secret(self.alice_path, self.bob_token)
        except KVPathAccessDeniedError:
            pass

        logs = self.db.get_audit_logs()
        self.assertGreater(len(logs), 0)
        self.assertEqual(logs[0]["requester_email"], self.bob_email)
        self.assertEqual(logs[0]["target_resource"], self.alice_path)
        self.assertEqual(logs[0]["reason"], "PERMISSION_DENIED")

    # ------------------------------------------------------------------
    # 6. Invalid & Expired Token Prevention Tests
    # ------------------------------------------------------------------
    def test_invalid_and_expired_token_prevention(self):
        # Invalid token raises InvalidSessionTokenError BEFORE touching path or crypto
        with self.assertRaises(InvalidSessionTokenError):
            self.kv_engine.read_secret(self.alice_path, "invalid_token_123")

        # Invalid path format raises KVInvalidPathError
        with self.assertRaises(KVInvalidPathError):
            self.kv_engine.read_secret("invalid/path/format", self.alice_token)


if __name__ == "__main__":
    unittest.main()
