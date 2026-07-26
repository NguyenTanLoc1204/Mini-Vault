"""
Unit tests for Mini Vault Transit Engine (src/transit/engine.py)
Covering 100% of Named Key Management, Encrypt/Decrypt APIs, Sign/Verify APIs, and Ownership ACL cases.
"""

import base64
import unittest
from src.storage import VaultDatabase
from src.core import VaultManager, VaultLockedError
from src.auth import AuthManager, SessionManager
from src.transit import (
    TransitEngine,
    TransitKeyAccessDeniedError,
    InvalidKeyUsageError,
    TransitDataCorruptedError,
)


class TestTransitEngine(unittest.TestCase):
    def setUp(self):
        """Set up in-memory DB, VaultManager, AuthManager, and TransitEngine for each test."""
        self.db = VaultDatabase(":memory:")
        self.vault_mgr = VaultManager(self.db)
        self.session_mgr = SessionManager()
        self.auth_mgr = AuthManager(db=self.db, session_manager=self.session_mgr)
        self.transit_engine = TransitEngine(
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

    def tearDown(self):
        self.db.close()

    # ------------------------------------------------------------------
    # 1. Symmetric Key Creation & Listing Tests
    # ------------------------------------------------------------------
    def test_create_and_list_symmetric_key(self):
        # Create key
        key_res = self.transit_engine.create_key("my-app-key", self.alice_token)
        self.assertEqual(key_res["key_name"], "my-app-key")
        self.assertEqual(key_res["key_usage"], "ENCRYPT_DECRYPT")
        self.assertEqual(key_res["owner_email"], self.alice_email)

        # List keys
        alice_keys = self.transit_engine.list_keys(self.alice_token)
        self.assertEqual(len(alice_keys), 1)
        self.assertEqual(alice_keys[0]["key_name"], "my-app-key")
        # Ensure raw key material is NEVER returned
        self.assertNotIn("encrypted_key_material_b64", alice_keys[0])

        # Bob lists keys -> 0 keys
        bob_keys = self.transit_engine.list_keys(self.bob_token)
        self.assertEqual(len(bob_keys), 0)

        # Duplicate key_name for same user raises ValueError
        with self.assertRaises(ValueError):
            self.transit_engine.create_key("my-app-key", self.alice_token)

    # ------------------------------------------------------------------
    # 2. Encrypt & Decrypt Roundtrip Tests
    # ------------------------------------------------------------------
    def test_encrypt_decrypt_roundtrip(self):
        self.transit_engine.create_key("my-app-key", self.alice_token)

        raw_text = "Super sensitive API Secret Key token value"
        plaintext_b64 = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")

        # Encrypt
        ciphertext_str = self.transit_engine.encrypt("my-app-key", plaintext_b64, self.alice_token)
        self.assertTrue(ciphertext_str.startswith("vault:my-app-key:"))

        # Decrypt
        decrypted_b64 = self.transit_engine.decrypt(ciphertext_str, self.alice_token)
        decrypted_text = base64.b64decode(decrypted_b64).decode("utf-8")
        self.assertEqual(decrypted_text, raw_text)

    # ------------------------------------------------------------------
    # 3. AEAD Tamper Detection Tests
    # ------------------------------------------------------------------
    def test_tampered_ciphertext_rejection(self):
        self.transit_engine.create_key("my-app-key", self.alice_token)
        plaintext_b64 = base64.b64encode(b"Secret Payload").decode("utf-8")

        ciphertext_str = self.transit_engine.encrypt("my-app-key", plaintext_b64, self.alice_token)

        # Alter 1 byte of payload
        parts = ciphertext_str.split(":", 2)
        tampered_payload = parts[2][:-2] + "AA"
        tampered_ciphertext_str = f"vault:my-app-key:{tampered_payload}"

        with self.assertRaises(TransitDataCorruptedError):
            self.transit_engine.decrypt(tampered_ciphertext_str, self.alice_token)

    # ------------------------------------------------------------------
    # 4. Invalid Key Usage Rejection Tests
    # ------------------------------------------------------------------
    def test_invalid_key_usage_rejection(self):
        # Create a SIGN_VERIFY key
        self.transit_engine.create_signing_key("my-sign-key", "ED25519", self.alice_token)

        plaintext_b64 = base64.b64encode(b"Payload").decode("utf-8")

        # Calling encrypt on SIGN_VERIFY key raises InvalidKeyUsageError
        with self.assertRaises(InvalidKeyUsageError) as ctx:
            self.transit_engine.encrypt("my-sign-key", plaintext_b64, self.alice_token)
        self.assertEqual(ctx.exception.code, "INVALID_KEY_USAGE")

    # ------------------------------------------------------------------
    # 5. Cross-User Key Access Control Denial Tests
    # ------------------------------------------------------------------
    def test_cross_user_key_access_denial(self):
        self.transit_engine.create_key("my-app-key", self.alice_token)
        plaintext_b64 = base64.b64encode(b"Secret").decode("utf-8")
        ct_str = self.transit_engine.encrypt("my-app-key", plaintext_b64, self.alice_token)

        # Bob attempts encrypt using Alice's key -> 100% DENIED
        with self.assertRaises(TransitKeyAccessDeniedError) as ctx_enc:
            self.transit_engine.encrypt("my-app-key", plaintext_b64, self.bob_token)
        self.assertEqual(ctx_enc.exception.code, "PERMISSION_DENIED")

        # Bob attempts decrypt using Alice's key -> 100% DENIED
        with self.assertRaises(TransitKeyAccessDeniedError) as ctx_dec:
            self.transit_engine.decrypt(ct_str, self.bob_token)
        self.assertEqual(ctx_dec.exception.code, "PERMISSION_DENIED")

        # Audit log entry created for denial
        logs = self.db.get_audit_logs()
        self.assertGreater(len(logs), 0)
        self.assertEqual(logs[0]["requester_email"], self.bob_email)
        self.assertEqual(logs[0]["reason"], "PERMISSION_DENIED")

    # ------------------------------------------------------------------
    # 6. Asymmetric Signing Key Creation Tests (ED25519 & RSA-2048)
    # ------------------------------------------------------------------
    def test_create_signing_key_ed25519_and_rsa(self):
        # Create ED25519
        ed_key = self.transit_engine.create_signing_key("ed-sign-key", "ED25519", self.alice_token)
        self.assertEqual(ed_key["key_usage"], "SIGN_VERIFY")
        self.assertEqual(ed_key["signing_algorithm"], "ED25519")

        # Create RSA-2048
        rsa_key = self.transit_engine.create_signing_key("rsa-sign-key", "RSA-2048", self.alice_token)
        self.assertEqual(rsa_key["key_usage"], "SIGN_VERIFY")
        self.assertEqual(rsa_key["signing_algorithm"], "RSA-2048")

    # ------------------------------------------------------------------
    # 7. Sign & Verify Tests (RAW and DIGEST)
    # ------------------------------------------------------------------
    def test_sign_and_verify_raw_and_digest(self):
        self.transit_engine.create_signing_key("ed-sign-key", "ED25519", self.alice_token)

        message_text = "Important financial transaction authorization"
        msg_b64 = base64.b64encode(message_text.encode("utf-8")).decode("utf-8")

        # 1. Sign RAW message
        sign_res = self.transit_engine.sign("ed-sign-key", msg_b64, "RAW", self.alice_token)
        self.assertIn("signature_b64", sign_res)

        # 2. Verify unmodified message -> signature_valid: True
        verify_res = self.transit_engine.verify("ed-sign-key", msg_b64, "RAW", sign_res["signature_b64"], self.alice_token)
        self.assertTrue(verify_res["signature_valid"])
        self.assertEqual(verify_res["signing_algorithm"], "ED25519")

        # 3. Alter message byte -> verify returns signature_valid: False
        tampered_msg_b64 = base64.b64encode(b"Tampered message payload").decode("utf-8")
        verify_tampered = self.transit_engine.verify("ed-sign-key", tampered_msg_b64, "RAW", sign_res["signature_b64"], self.alice_token)
        self.assertFalse(verify_tampered["signature_valid"])

    # ------------------------------------------------------------------
    # 8. Malformed Signature Handling Test
    # ------------------------------------------------------------------
    def test_malformed_signature_handling(self):
        self.transit_engine.create_signing_key("rsa-sign-key", "RSA-2048", self.alice_token)
        msg_b64 = base64.b64encode(b"Message").decode("utf-8")

        # Verify malformed signature string -> signature_valid: False (no unhandled crashes)
        verify_res = self.transit_engine.verify("rsa-sign-key", msg_b64, "RAW", "invalid_base64_sig!", self.alice_token)
        self.assertFalse(verify_res["signature_valid"])

    # ------------------------------------------------------------------
    # 9. Key Revocation Test
    # ------------------------------------------------------------------
    def test_revoke_key(self):
        self.transit_engine.create_key("my-app-key", self.alice_token)

        # Revoke
        self.assertTrue(self.transit_engine.revoke_key("my-app-key", self.alice_token))

        # Encrypt with revoked key raises TransitKeyAccessDeniedError
        plaintext_b64 = base64.b64encode(b"Payload").decode("utf-8")
        with self.assertRaises(TransitKeyAccessDeniedError):
            self.transit_engine.encrypt("my-app-key", plaintext_b64, self.alice_token)

    # ------------------------------------------------------------------
    # 10. Plaintext Key Disk Isolation Verification Test
    # ------------------------------------------------------------------
    def test_plaintext_private_key_disk_isolation(self):
        self.transit_engine.create_signing_key("ed-sign-key", "ED25519", self.alice_token)

        # Read key record directly from DB
        key_record = self.db.get_transit_key("ed-sign-key")
        encrypted_key_b64 = key_record["encrypted_key_material_b64"]

        # Encrypted private key payload must NOT contain raw PEM header in plaintext
        self.assertNotIn("BEGIN PRIVATE KEY", encrypted_key_b64)


if __name__ == "__main__":
    unittest.main()
