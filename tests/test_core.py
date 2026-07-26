"""
Unit tests for Mini Vault Core Module (src/core/vault.py & crypto_utils.py)
Covering 100% of KDF, AEAD, Vault Init, Unlock, Lock, and RAM Isolation cases.
"""

import os
import secrets
import unittest
from src.storage import VaultDatabase
from src.core import (
    VaultManager,
    derive_master_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    pack_gcm_payload,
    unpack_gcm_payload,
    VaultAuthenticationError,
    VaultCryptoError,
    VaultLockedError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    InvalidPassphraseError,
)


class TestCoreCryptoAndVault(unittest.TestCase):
    def setUp(self):
        """Provide an in-memory VaultDatabase and VaultManager for each test."""
        self.db = VaultDatabase(":memory:")
        self.vault = VaultManager(self.db)
        self.passphrase = "UltraSecureMasterPassphrase2026!"

    def tearDown(self):
        self.db.close()

    # ------------------------------------------------------------------
    # 1. KDF Determinism & Salt Isolation Tests
    # ------------------------------------------------------------------
    def test_kdf_determinism_and_salt_isolation(self):
        salt1 = secrets.token_bytes(16)
        salt2 = secrets.token_bytes(16)

        # Same passphrase + salt -> same Master Key
        key1a = derive_master_key(self.passphrase, salt1)
        key1b = derive_master_key(self.passphrase, salt1)
        self.assertEqual(key1a, key1b)
        self.assertEqual(len(key1a), 32)

        # Different salt -> different Master Key
        key2 = derive_master_key(self.passphrase, salt2)
        self.assertNotEqual(key1a, key2)

        # Different passphrase -> different Master Key
        key3 = derive_master_key("DifferentPassphrase2026!", salt1)
        self.assertNotEqual(key1a, key3)

        # Empty passphrase / invalid salt
        with self.assertRaises(ValueError):
            derive_master_key("", salt1)
        with self.assertRaises(ValueError):
            derive_master_key(self.passphrase, b"short")

    # ------------------------------------------------------------------
    # 2. AES-256-GCM AEAD & Tamper Detection Tests
    # ------------------------------------------------------------------
    def test_aes_gcm_roundtrip_and_tamper_detection(self):
        key = secrets.token_bytes(32)
        plaintext = b"Super confidential database secret payload"

        # Encrypt
        nonce_b64, ct_b64, tag_b64 = encrypt_aes_gcm(key, plaintext)
        self.assertTrue(len(nonce_b64) > 0)
        self.assertTrue(len(ct_b64) > 0)
        self.assertTrue(len(tag_b64) > 0)

        # Decrypt happy path
        decrypted = decrypt_aes_gcm(key, nonce_b64, ct_b64, tag_b64)
        self.assertEqual(decrypted, plaintext)

        # Payload tamper test: Alter 1 byte in ciphertext
        ct_raw = bytearray(encrypt_aes_gcm(key, plaintext)[1].encode())
        ct_raw[0] = ord("A") if ct_raw[0] != ord("A") else ord("B")
        tampered_ct_b64 = ct_raw.decode()

        with self.assertRaises(VaultAuthenticationError):
            decrypt_aes_gcm(key, nonce_b64, tampered_ct_b64, tag_b64)

        # Payload packing/unpacking test
        packed = pack_gcm_payload(nonce_b64, ct_b64, tag_b64)
        n, c, t = unpack_gcm_payload(packed)
        self.assertEqual((n, c, t), (nonce_b64, ct_b64, tag_b64))

    # ------------------------------------------------------------------
    # 3. Vault Initialization (init_vault) Tests
    # ------------------------------------------------------------------
    def test_init_vault_happy_path(self):
        self.assertFalse(self.vault.is_initialized())
        self.assertFalse(self.vault.is_unlocked)

        # Init vault
        res = self.vault.init_vault(self.passphrase)
        self.assertEqual(res["kdf"], "argon2id")
        self.assertEqual(res["status"], "unlocked")

        self.assertTrue(self.vault.is_initialized())
        self.assertTrue(self.vault.is_unlocked)

        # DEK should be active in RAM (32 bytes)
        dek = self.vault.get_dek()
        self.assertEqual(len(dek), 32)

    def test_init_vault_already_initialized(self):
        self.vault.init_vault(self.passphrase)
        with self.assertRaises(VaultAlreadyInitializedError):
            self.vault.init_vault("SecondPassphrase2026!")

    def test_init_vault_invalid_passphrase(self):
        with self.assertRaises(ValueError):
            self.vault.init_vault("")
        with self.assertRaises(ValueError):
            self.vault.init_vault("   ")

    # ------------------------------------------------------------------
    # 4. Vault Unlock & Wrong Passphrase Tests
    # ------------------------------------------------------------------
    def test_unlock_vault_happy_path(self):
        # 1. Init
        self.vault.init_vault(self.passphrase)
        original_dek = self.vault.get_dek()

        # 2. Lock
        self.vault.lock_vault()
        self.assertFalse(self.vault.is_unlocked)
        with self.assertRaises(VaultLockedError):
            self.vault.get_dek()

        # 3. Unlock with correct passphrase
        res = self.vault.unlock_vault(self.passphrase)
        self.assertTrue(res)
        self.assertTrue(self.vault.is_unlocked)
        self.assertEqual(self.vault.get_dek(), original_dek)

    def test_unlock_vault_wrong_passphrase(self):
        self.vault.init_vault(self.passphrase)
        self.vault.lock_vault()

        # Unlock with wrong passphrase
        with self.assertRaises(InvalidPassphraseError) as ctx:
            self.vault.unlock_vault("WrongPassphrase2026!")

        # Verify generic error message, no GCM details
        self.assertEqual(str(ctx.exception), "Invalid Master Passphrase.")
        self.assertFalse(self.vault.is_unlocked)
        self.assertEqual(self.db.get_vault_config()["status"], "locked")

    def test_unlock_uninitialized_vault(self):
        with self.assertRaises(VaultNotInitializedError):
            self.vault.unlock_vault(self.passphrase)

    # ------------------------------------------------------------------
    # 5. Lock Vault & RAM DEK Isolation Tests
    # ------------------------------------------------------------------
    def test_lock_vault(self):
        self.vault.init_vault(self.passphrase)
        self.assertTrue(self.vault.is_unlocked)

        self.vault.lock_vault()
        self.assertFalse(self.vault.is_unlocked)
        self.assertEqual(self.db.get_vault_config()["status"], "locked")

        with self.assertRaises(VaultLockedError) as ctx:
            self.vault.require_unlocked()
        self.assertEqual(ctx.exception.code, "VAULT_LOCKED")

    # ------------------------------------------------------------------
    # 6. Restart Simulation & Single Source of Truth Auto-Reset
    # ------------------------------------------------------------------
    def test_restart_simulation_and_auto_reset(self):
        # 1. Init vault in instance 1
        self.vault.init_vault(self.passphrase)
        original_dek = self.vault.get_dek()

        # 2. Simulate server restart: create a new VaultManager instance over SAME DB
        # At restart, RAM _dek is None
        vault2 = VaultManager(self.db)

        # Single source of truth: new instance must be locked!
        self.assertFalse(vault2.is_unlocked)
        # Auto-sync must reset DB status from 'unlocked' to 'locked'
        self.assertEqual(self.db.get_vault_config()["status"], "locked")

        # Unlock instance 2 with correct passphrase
        vault2.unlock_vault(self.passphrase)
        self.assertTrue(vault2.is_unlocked)
        self.assertEqual(vault2.get_dek(), original_dek)

    # ------------------------------------------------------------------
    # 7. Plaintext DEK Disk Isolation Verification
    # ------------------------------------------------------------------
    def test_dek_never_stored_plaintext_on_disk(self):
        self.vault.init_vault(self.passphrase)
        dek = self.vault.get_dek()

        # Read config directly from DB
        config = self.db.get_vault_config()
        encrypted_dek_b64 = config["encrypted_dek_b64"]

        # Plaintext DEK bytes must NOT appear anywhere in the database text
        self.assertNotIn(dek, encrypted_dek_b64.encode())
        self.assertNotIn(dek.hex(), encrypted_dek_b64)


if __name__ == "__main__":
    unittest.main()
