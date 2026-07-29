"""
KV Engine: Feature 1 Secure Storage (AEAD Encrypted-at-Rest & Ownership ACL)
"""

import json
from typing import Dict, Optional, Tuple, Any

from src.storage import VaultDatabase
from src.core import (
    VaultManager,
    VaultLockedError,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    VaultAuthenticationError,
)
from src.auth import (
    AuthManager,
    InvalidSessionTokenError,
    SessionExpiredError,
)


class KVEngineError(Exception):
    """Base exception for KV Engine operations."""
    pass


class KVPathAccessDeniedError(KVEngineError):
    """Raised when access to a secret path is denied ('PERMISSION_DENIED')."""
    def __init__(self, message: str = "Permission denied or resource not found."):
        super().__init__(message)
        self.code = "PERMISSION_DENIED"


class KVNotFoundError(KVEngineError):
    """Raised when a secret path is not found ('NOT_FOUND')."""
    def __init__(self, message: str = "Secret path not found."):
        super().__init__(message)
        self.code = "NOT_FOUND"


class KVDataCorruptedError(KVEngineError):
    """Raised when ciphertext or AEAD tag on disk is tampered/corrupted ('DATA_CORRUPTED')."""
    def __init__(self, message: str = "Data on disk has been tampered with or corrupted."):
        super().__init__(message)
        self.code = "DATA_CORRUPTED"


class KVInvalidPathError(KVEngineError):
    """Raised when path format is invalid (must be 'secret/<owner_email>/...')."""
    pass


class KVEngine:
    def __init__(
        self,
        vault_manager: VaultManager,
        auth_manager: AuthManager,
        db: Optional[VaultDatabase] = None,
    ):
        self.vault_manager = vault_manager
        self.auth_manager = auth_manager
        self.db = db if db is not None else vault_manager.db

    def _parse_and_validate_path(self, path: str) -> Tuple[str, str]:
        """
        Validate path format.
        MUST match 'secret/<owner_email>/<secret_name>'.
        Returns (clean_path, owner_email).
        """
        if not path or not path.strip():
            raise KVInvalidPathError("Path cannot be empty.")

        clean_path = path.strip().strip("/")
        parts = clean_path.split("/")

        if len(parts) < 3 or parts[0] != "secret":
            raise KVInvalidPathError("Path format must be 'secret/<email>/<name>'.")

        owner_email = parts[1].lower().strip()
        if not owner_email or "@" not in owner_email:
            raise KVInvalidPathError("Invalid owner email prefix in path.")

        return clean_path, owner_email

    def _enforce_path_access(
        self, path: str, token: str, action: str
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Enforce Ownership Access Control (Section 1.2):
        1. Verifies session token.
        2. Validates path format: 'secret/<email>/...'.
        3. Compares caller email in token with path owner email.
        4. If mismatched: Refuses BEFORE touching any crypto, returns generic PERMISSION_DENIED, logs audit event.
        """
        # 1. Verify session token
        session = self.auth_manager.verify_session(token)
        caller_email = session["email"].lower().strip()

        # 2. Parse and validate path
        clean_path, owner_email = self._parse_and_validate_path(path)

        # 3. Ownership check: caller MUST be the owner of the namespace
        if caller_email != owner_email:
            # Log denied access attempt
            self.db.log_audit_event(
                requester_email=caller_email,
                target_resource=clean_path,
                action=action.upper(),
                reason="PERMISSION_DENIED",
            )
            # Generic error that doesn't reveal path existence
            raise KVPathAccessDeniedError()

        return clean_path, session

    def write_secret(
        self, path: str, data: Dict[str, Any], token: str
    ) -> Dict[str, Any]:
        """
        Write a secret (Section 1.1 & 1.2):
        1. Enforces path ownership ACL (secret/<email>/...).
        2. Requires Vault to be UNLOCKED.
        3. Encrypts JSON payload using AES-256-GCM + DEK in RAM + fresh 12-byte Nonce.
        4. Writes ciphertext + nonce + tag to database. Overwrites if path exists.
        """
        if not isinstance(data, dict):
            raise ValueError("Data payload must be a JSON object (dictionary).")

        # 1. Enforce ACL BEFORE touching crypto
        clean_path, session = self._enforce_path_access(path, token, action="WRITE")

        # 2. Ensure Vault is unlocked
        self.vault_manager.require_unlocked()
        dek = self.vault_manager.get_dek()

        # 3. Serialize data to JSON bytes & encrypt via AES-256-GCM
        try:
            json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to serialize data to JSON: {e}") from e

        nonce_b64, ct_b64, tag_b64 = encrypt_aes_gcm(dek, json_bytes)

        # 4. Save to database kv_secrets table
        record = self.db.put_kv_secret(
            path=clean_path,
            owner_id=session["user_id"],
            nonce_b64=nonce_b64,
            ciphertext_b64=ct_b64,
            tag_b64=tag_b64,
        )

        return {
            "path": record["path"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
        }

    def read_secret(self, path: str, token: str) -> Dict[str, Any]:
        """
        Read a secret (Section 1.1 & 1.2):
        1. Enforces path ownership ACL.
        2. Requires Vault to be UNLOCKED.
        3. Fetches record from database.
        4. Decrypts payload using DEK + AES-256-GCM. Refuses outright on tag mismatch.
        5. Returns decrypted JSON dictionary.
        """
        # 1. Enforce ACL BEFORE touching crypto
        clean_path, session = self._enforce_path_access(path, token, action="READ")

        # 2. Ensure Vault is unlocked
        self.vault_manager.require_unlocked()
        dek = self.vault_manager.get_dek()

        # 3. Fetch record from DB
        record = self.db.get_kv_secret(clean_path)
        if not record:
            raise KVNotFoundError()

        # 4. Decrypt & verify GCM tag
        try:
            decrypted_bytes = decrypt_aes_gcm(
                key=dek,
                nonce_b64=record["nonce_b64"],
                ciphertext_b64=record["ciphertext_b64"],
                tag_b64=record["tag_b64"],
            )
        except VaultAuthenticationError:
            # GCM tag mismatch or tampered data -> Refuse outright
            raise KVDataCorruptedError()

        # 5. Parse JSON data
        try:
            decrypted_data = json.loads(decrypted_bytes.decode("utf-8"))
            return decrypted_data
        except Exception as e:
            raise KVDataCorruptedError("Failed to parse decrypted payload as JSON.") from e

    def delete_secret(self, path: str, token: str) -> bool:
        """
        Delete a secret (Section 1.1 & 1.2):
        1. Enforces path ownership ACL.
        2. Permanently deletes record from database.
        """
        # 1. Enforce ACL
        clean_path, session = self._enforce_path_access(path, token, action="DELETE")
        
        # check vault lock before
        self.vault_manager.require_unlocked()

        # 2. Delete from DB
        deleted = self.db.delete_kv_secret(clean_path)
        return deleted
