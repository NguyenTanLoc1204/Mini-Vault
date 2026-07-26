"""
Core Module: Vault Initialization, Unlock, Argon2id KDF, and DEK Key Management
"""

from src.core.crypto_utils import (
    derive_master_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    pack_gcm_payload,
    unpack_gcm_payload,
    VaultCryptoError,
    VaultAuthenticationError,
)
from src.core.vault import (
    VaultManager,
    VaultError,
    VaultLockedError,
    VaultAlreadyInitializedError,
    VaultNotInitializedError,
    InvalidPassphraseError,
)

__all__ = [
    "derive_master_key",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "pack_gcm_payload",
    "unpack_gcm_payload",
    "VaultCryptoError",
    "VaultAuthenticationError",
    "VaultManager",
    "VaultError",
    "VaultLockedError",
    "VaultAlreadyInitializedError",
    "VaultNotInitializedError",
    "InvalidPassphraseError",
]
