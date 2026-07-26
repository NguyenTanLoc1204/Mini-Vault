"""
Vault Manager Core: Initialization, Unlock/Lock Lifecycle, and DEK RAM Management
"""

import base64
import secrets
from typing import Dict, Optional, Any
from src.storage import VaultDatabase
from src.core.crypto_utils import (
    ARGON2_SALT_LEN,
    ARGON2_KEY_LEN,
    derive_master_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    pack_gcm_payload,
    unpack_gcm_payload,
    VaultAuthenticationError,
)


class VaultError(Exception):
    """Base exception for Vault operations."""
    pass


class VaultLockedError(VaultError):
    """Raised when attempting operations while the Vault is locked ('VAULT_LOCKED')."""
    def __init__(self, message: str = "Vault is locked. Please unlock first."):
        super().__init__(message)
        self.code = "VAULT_LOCKED"


class VaultAlreadyInitializedError(VaultError):
    """Raised when attempting to initialize an already-initialized Vault."""
    pass


class VaultNotInitializedError(VaultError):
    """Raised when attempting to unlock a Vault that has not been initialized."""
    pass


class InvalidPassphraseError(VaultError):
    """Raised when Master Passphrase decryption fails (generic error, no details leaked)."""
    pass


class VaultManager:
    def __init__(self, db: Optional[VaultDatabase] = None):
        self.db = db if db is not None else VaultDatabase()
        # Plaintext Data Encryption Key (DEK) lives EXCLUSIVELY in RAM
        self._dek: Optional[bytes] = None
        self._sync_status_on_startup()

    def _sync_status_on_startup(self) -> None:
        """
        Auto-Sync on Startup:
        If server crashed or restarted, DB status might say 'unlocked' while _dek in RAM is None.
        Automatically reset DB status to 'locked' to maintain single source of truth.
        """
        config = self.db.get_vault_config()
        if config and config.get("status") != "locked" and self._dek is None:
            self.db.update_vault_status("locked")

    @property
    def is_unlocked(self) -> bool:
        """Single Source of Truth: Vault is unlocked IF AND ONLY IF DEK is active in RAM."""
        return self._dek is not None

    def is_initialized(self) -> bool:
        """Check if Vault config exists in database."""
        return self.db.get_vault_config() is not None

    def get_dek(self) -> bytes:
        """Retrieve in-memory DEK. Raises VaultLockedError if locked."""
        if not self.is_unlocked or self._dek is None:
            raise VaultLockedError()
        return self._dek

    def init_vault(self, master_passphrase: str) -> Dict[str, Any]:
        """
        Initialize Vault with a Master Passphrase (Section 0.1):
        1. Derive Master Key via Argon2id + random 16-byte Salt.
        2. Generate 32-byte random DEK (`secrets.token_bytes(32)`).
        3. Encrypt DEK using Master Key (AES-256-GCM).
        4. Save config to DB and hold DEK in RAM (Vault becomes unlocked).
        """
        if self.is_initialized():
            raise VaultAlreadyInitializedError("Vault is already initialized.")
        if not master_passphrase or not master_passphrase.strip():
            raise ValueError("Master Passphrase cannot be empty or whitespace.")

        # 1. Generate 16-byte random salt & derive Master Key (256-bit)
        salt = secrets.token_bytes(ARGON2_SALT_LEN)
        master_key = derive_master_key(master_passphrase.strip(), salt)

        # 2. Generate random 256-bit DEK
        dek = secrets.token_bytes(ARGON2_KEY_LEN)

        # 3. Encrypt DEK with Master Key via AES-256-GCM
        nonce_b64, ct_b64, tag_b64 = encrypt_aes_gcm(master_key, dek)
        encrypted_dek_b64 = pack_gcm_payload(nonce_b64, ct_b64, tag_b64)
        salt_b64 = base64.b64encode(salt).decode("utf-8")

        # 4. Save to database config table (status="unlocked")
        config = self.db.save_vault_config(
            kdf="argon2id",
            kdf_salt_b64=salt_b64,
            encrypted_dek_b64=encrypted_dek_b64,
            status="unlocked",
        )

        # 5. Hold DEK in RAM
        self._dek = dek

        return {
            "kdf": config["kdf"],
            "kdf_salt_b64": config["kdf_salt_b64"],
            "encrypted_dek_b64": config["encrypted_dek_b64"],
            "status": "unlocked",
        }

    def unlock_vault(self, master_passphrase: str) -> bool:
        """
        Unlock Vault with Master Passphrase (Section 0.1):
        1. Re-derive Master Key using Argon2id + salt from DB.
        2. Decrypt DEK using Master Key (AES-256-GCM).
        3. On success: Store DEK in RAM & set DB status to 'unlocked'.
        4. On failure: Keep DEK as None, DB status 'locked', raise generic InvalidPassphraseError.
        """
        config = self.db.get_vault_config()
        if not config:
            raise VaultNotInitializedError("Vault has not been initialized yet.")
        if not master_passphrase or not master_passphrase.strip():
            raise InvalidPassphraseError("Invalid Master Passphrase.")

        salt_b64 = config["kdf_salt_b64"]
        encrypted_dek_b64 = config["encrypted_dek_b64"]

        try:
            salt = base64.b64decode(salt_b64)
            master_key = derive_master_key(master_passphrase.strip(), salt)
            nonce_b64, ct_b64, tag_b64 = unpack_gcm_payload(encrypted_dek_b64)
            decrypted_dek = decrypt_aes_gcm(master_key, nonce_b64, ct_b64, tag_b64)
        except VaultAuthenticationError:
            # GCM tag mismatch or wrong passphrase -> Fail closed
            self._dek = None
            self.db.update_vault_status("locked")
            raise InvalidPassphraseError("Invalid Master Passphrase.")
        except Exception:
            self._dek = None
            self.db.update_vault_status("locked")
            raise InvalidPassphraseError("Invalid Master Passphrase.")

        # Success: Load DEK to RAM & update DB status to unlocked
        self._dek = decrypted_dek
        self.db.update_vault_status("unlocked")
        return True

    def lock_vault(self) -> None:
        """Lock Vault: Clear plaintext DEK from RAM and set DB status to 'locked'."""
        self._dek = None
        if self.is_initialized():
            self.db.update_vault_status("locked")

    def require_unlocked(self) -> None:
        """Helper assertion method for API handlers to verify Vault is unlocked."""
        if not self.is_unlocked:
            raise VaultLockedError()
