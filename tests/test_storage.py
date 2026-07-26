"""
Unit tests for Mini Vault Storage Module (src/storage/db.py)
Covering 100% of CRUD operations, edge cases, boundaries, and SQL constraints.
"""

import sqlite3
import unittest
from src.storage import VaultDatabase


class TestVaultDatabase(unittest.TestCase):
    def setUp(self):
        """Provide an in-memory VaultDatabase instance for each test."""
        self.db = VaultDatabase(":memory:")

    def tearDown(self):
        """Clean up connection after test."""
        self.db.close()

    # ------------------------------------------------------------------
    # 1. Vault Config Edge Cases & Constraints
    # ------------------------------------------------------------------
    def test_vault_config_ops_and_overwrites(self):
        # Initially no config
        self.assertIsNone(self.db.get_vault_config())

        # Initial Save
        config1 = self.db.save_vault_config(
            kdf_salt_b64="c2FsdDFf=",
            encrypted_dek_b64="ZW5jcnlwdGVkMV8=",
            status="locked",
        )
        self.assertEqual(config1["kdf"], "argon2id")
        self.assertEqual(config1["kdf_salt_b64"], "c2FsdDFf=")
        self.assertEqual(config1["status"], "locked")

        # Overwrite existing config (ID=1 ON CONFLICT)
        config2 = self.db.save_vault_config(
            kdf_salt_b64="c2FsdDJf=",
            encrypted_dek_b64="ZW5jcnlwdGVkMl8=",
            status="unlocked",
        )
        self.assertEqual(config2["kdf_salt_b64"], "c2FsdDJf=")
        self.assertEqual(config2["encrypted_dek_b64"], "ZW5jcnlwdGVkMl8=")
        self.assertEqual(config2["status"], "unlocked")

        # Update status python-level validation
        self.assertTrue(self.db.update_vault_status("locked"))
        self.assertEqual(self.db.get_vault_config()["status"], "locked")

        with self.assertRaises(ValueError):
            self.db.update_vault_status("invalid_status")

        # Database-level CHECK constraint validation
        conn = self.db.get_connection()
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE vault_config SET status = 'INVALID' WHERE id = 1;")

    # ------------------------------------------------------------------
    # 2. User Authentication Edge Cases & Normalization
    # ------------------------------------------------------------------
    def test_user_ops_edge_cases_and_normalization(self):
        raw_email = "   Alice.Smith@Domain.COM   "
        expected_email = "alice.smith@domain.com"
        pass_hash = "$2b$12$samplehashvaluehere..."

        # Create user with unnormalized email
        user = self.db.create_user(raw_email, pass_hash)
        self.assertGreater(user["id"], 0)
        self.assertEqual(user["email"], expected_email)

        # Lookup by unnormalized email
        fetched = self.db.get_user(" ALICE.SMITH@domain.com ")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], user["id"])

        # Lookup non-existent user
        self.assertIsNone(self.db.get_user("nonexistent@domain.com"))
        self.assertIsNone(self.db.get_user_by_id(99999))

        # Duplicate email constraint (case-insensitive duplicate check)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.create_user("alice.smith@domain.com", "another_hash")

        # Update failed attempts & lockout
        self.assertTrue(
            self.db.update_user_failed_attempts("ALICE.SMITH@domain.com", 3, "2026-07-26T20:00:00Z")
        )
        updated = self.db.get_user(expected_email)
        self.assertEqual(updated["failed_attempts"], 3)
        self.assertEqual(updated["lockout_until"], "2026-07-26T20:00:00Z")

        # Reset lockout
        self.assertTrue(self.db.reset_user_lockout(expected_email))
        reset_user = self.db.get_user(expected_email)
        self.assertEqual(reset_user["failed_attempts"], 0)
        self.assertIsNone(reset_user["lockout_until"])

        # Update non-existent user returns False
        self.assertFalse(self.db.update_user_failed_attempts("unknown@domain.com", 1))
        self.assertFalse(self.db.reset_user_lockout("unknown@domain.com"))

    # ------------------------------------------------------------------
    # 3. KV Secrets Edge Cases & Foreign Key Cascade Delete
    # ------------------------------------------------------------------
    def test_kv_secrets_edge_cases_and_cascade_delete(self):
        alice = self.db.create_user("alice@example.com", "hash")
        path = "  secret/alice@example.com/db  "
        clean_path = "secret/alice@example.com/db"
        nonce = "bm9uY2VfMTJfYnl0ZXM="
        ct = "Y2lwaGVydGV4dF9kYXRh"
        tag = "dGFnXzE2X2J5dGVz"

        # Create KV secret with unstripped path
        sec = self.db.put_kv_secret(path, alice["id"], nonce, ct, tag)
        self.assertEqual(sec["path"], clean_path)
        self.assertEqual(sec["owner_id"], alice["id"])
        self.assertEqual(sec["owner_email"], "alice@example.com")

        # Overwrite existing secret
        updated_sec = self.db.put_kv_secret(clean_path, alice["id"], nonce, "NEW_CT", tag)
        self.assertEqual(updated_sec["ciphertext_b64"], "NEW_CT")

        # Non-existent lookup
        self.assertIsNone(self.db.get_kv_secret("secret/nonexistent"))

        # Foreign Key constraint: Non-existent owner_id raises IntegrityError
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.put_kv_secret("secret/invalid/path", 99999, nonce, ct, tag)

        # Test CASCADE DELETE when User is deleted
        self.assertTrue(self.db.delete_user(alice["id"]))

        # Secret should be automatically cascade-deleted
        self.assertIsNone(self.db.get_kv_secret(clean_path))

    # ------------------------------------------------------------------
    # 4. Transit Keys Edge Cases, Constraints & Cascade Delete
    # ------------------------------------------------------------------
    def test_transit_keys_constraints_and_cascade_delete(self):
        alice = self.db.create_user("alice@example.com", "hash")
        bob = self.db.create_user("bob@example.com", "hash")

        # Create Symmetric Key
        key1 = self.db.save_transit_key(
            key_name="my-app-key",
            owner_id=alice["id"],
            key_usage="ENCRYPT_DECRYPT",
            encrypted_key_material_b64="enc_key_1",
        )
        self.assertEqual(key1["key_name"], "my-app-key")

        # Create Asymmetric Key
        key2 = self.db.save_transit_key(
            key_name="my-sign-key",
            owner_id=alice["id"],
            key_usage="SIGN_VERIFY",
            signing_algorithm="ED25519",
            encrypted_key_material_b64="enc_key_2",
            public_key_b64="pub_key_2",
        )
        self.assertEqual(key2["signing_algorithm"], "ED25519")

        # Duplicate key_name constraint (PRIMARY KEY violation)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.save_transit_key(
                key_name="my-app-key",
                owner_id=bob["id"],
                key_usage="ENCRYPT_DECRYPT",
                encrypted_key_material_b64="other_key",
            )

        # Invalid key_usage CHECK constraint
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.save_transit_key(
                key_name="invalid-usage-key",
                owner_id=alice["id"],
                key_usage="INVALID_USAGE",
                encrypted_key_material_b64="key",
            )

        # Non-existent FK constraint
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.save_transit_key(
                key_name="invalid-fk-key",
                owner_id=99999,
                key_usage="ENCRYPT_DECRYPT",
                encrypted_key_material_b64="key",
            )

        # List keys
        self.assertEqual(len(self.db.list_transit_keys(alice["id"])), 2)
        self.assertEqual(len(self.db.list_transit_keys(bob["id"])), 0)

        # Test CASCADE DELETE when User is deleted by email
        self.assertTrue(self.db.delete_user_by_email("alice@example.com"))

        self.assertIsNone(self.db.get_transit_key("my-app-key"))
        self.assertEqual(len(self.db.list_transit_keys(alice["id"])), 0)

    # ------------------------------------------------------------------
    # 5. Audit Logs Limits & Ordering
    # ------------------------------------------------------------------
    def test_audit_logs_limits_and_ordering(self):
        for i in range(5):
            self.db.log_audit_event(
                requester_email=f"user{i}@example.com",
                target_resource=f"secret/path_{i}",
                action="READ",
                reason="PERMISSION_DENIED",
            )

        # Fetch with limit
        logs_limited = self.db.get_audit_logs(limit=3)
        self.assertEqual(len(logs_limited), 3)

        # Check descending order (latest event first)
        self.assertEqual(logs_limited[0]["requester_email"], "user4@example.com")
        self.assertEqual(logs_limited[1]["requester_email"], "user3@example.com")
        self.assertEqual(logs_limited[2]["requester_email"], "user2@example.com")


if __name__ == "__main__":
    unittest.main()
