"""
Cryptographic Utilities for Mini Vault: Argon2id KDF & AES-256-GCM AEAD
"""

import base64
import json
import os
from typing import Tuple
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultCryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class VaultAuthenticationError(VaultCryptoError):
    """Raised when AEAD tag validation fails or payload is tampered."""
    pass


# Default Argon2id Parameters (RFC 9106 recommended for key derivation)
ARGON2_SALT_LEN = 16       # 16 bytes (128 bits)
ARGON2_KEY_LEN = 32        # 32 bytes (256 bits for AES-256)
ARGON2_TIME_COST = 3       # 3 iterations
ARGON2_MEMORY_COST = 65536 # 64 MB (65,536 KiB)
ARGON2_PARALLELISM = 4     # 4 threads


def derive_master_key(
    passphrase: str,
    salt: bytes,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    parallelism: int = ARGON2_PARALLELISM,
    key_len: int = ARGON2_KEY_LEN,
) -> bytes:
    """
    Derive a 256-bit cryptographic Master Key from a passphrase and salt using Argon2id.
    """
    if not passphrase:
        raise ValueError("Passphrase cannot be empty")
    if not salt or len(salt) < 8:
        raise ValueError("Salt must be at least 8 bytes long")

    try:
        master_key = low_level.hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_len,
            type=low_level.Type.ID,
        )
        return master_key
    except Exception as e:
        raise VaultCryptoError(f"KDF execution failed: {e}") from e


def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> Tuple[str, str, str]:
    """
    Encrypt plaintext using AES-256-GCM with a fresh random 12-byte Nonce.
    Returns (nonce_b64, ciphertext_b64, tag_b64).
    """
    if not key or len(key) != 32:
        raise ValueError("Encryption key must be exactly 32 bytes (256 bits)")

    # 12-byte (96-bit) random nonce for GCM mode
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    # AESGCM.encrypt appends 16-byte tag to the end of ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Split ciphertext and 16-byte authentication tag
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    nonce_b64 = base64.b64encode(nonce).decode("utf-8")
    ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")
    tag_b64 = base64.b64encode(tag).decode("utf-8")

    return nonce_b64, ciphertext_b64, tag_b64


def decrypt_aes_gcm(key: bytes, nonce_b64: str, ciphertext_b64: str, tag_b64: str) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM and verify the 16-byte AEAD tag.
    Raises VaultAuthenticationError if GCM tag mismatch or data tampered.
    """
    if not key or len(key) != 32:
        raise ValueError("Decryption key must be exactly 32 bytes (256 bits)")

    try:
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        tag = base64.b64decode(tag_b64)
    except Exception as e:
        raise VaultCryptoError(f"Base64 decoding failed: {e}") from e

    if len(nonce) != 12:
        raise VaultCryptoError("Nonce must be 12 bytes")
    if len(tag) != 16:
        raise VaultAuthenticationError("Invalid authentication tag length")

    ct_with_tag = ciphertext + tag
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, associated_data=None)
        return plaintext
    except Exception as e:
        # Never leak details on GCM tag mismatch
        raise VaultAuthenticationError("Authentication tag mismatch or corrupted data") from e


def pack_gcm_payload(nonce_b64: str, ciphertext_b64: str, tag_b64: str) -> str:
    """Pack GCM components into a JSON-encoded Base64 string for storage."""
    payload_dict = {
        "n": nonce_b64,
        "c": ciphertext_b64,
        "t": tag_b64,
    }
    raw_json = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw_json).decode("utf-8")


def unpack_gcm_payload(payload_b64: str) -> Tuple[str, str, str]:
    """Unpack JSON-encoded Base64 string back into (nonce_b64, ciphertext_b64, tag_b64)."""
    try:
        raw_json = base64.b64decode(payload_b64).decode("utf-8")
        d = json.loads(raw_json)
        return d["n"], d["c"], d["t"]
    except Exception as e:
        raise VaultCryptoError(f"Malformed GCM payload format: {e}") from e
