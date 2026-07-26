"""
Transit Engine: Feature 2 Encryption & Signing as a Service
"""

import base64
import hashlib
import json
import secrets
from typing import Dict, List, Optional, Tuple, Any

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from src.storage import VaultDatabase
from src.core import (
    VaultManager,
    VaultLockedError,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    pack_gcm_payload,
    unpack_gcm_payload,
    VaultAuthenticationError,
)
from src.auth import AuthManager


class TransitEngineError(Exception):
    """Base exception for Transit Engine operations."""
    pass


class TransitKeyAccessDeniedError(TransitEngineError):
    """Raised when access to a named key is denied ('PERMISSION_DENIED')."""
    def __init__(self, message: str = "Permission denied or key not found."):
        super().__init__(message)
        self.code = "PERMISSION_DENIED"


class TransitKeyNotFoundError(TransitEngineError):
    """Raised when a named key is not found ('NOT_FOUND')."""
    def __init__(self, message: str = "Named key not found."):
        super().__init__(message)
        self.code = "NOT_FOUND"


class InvalidKeyUsageError(TransitEngineError):
    """Raised when key usage is invalid for the requested API ('INVALID_KEY_USAGE')."""
    def __init__(self, message: str = "Invalid key usage for requested operation."):
        super().__init__(message)
        self.code = "INVALID_KEY_USAGE"


class TransitDataCorruptedError(TransitEngineError):
    """Raised when ciphertext format or GCM tag validation fails ('DATA_CORRUPTED')."""
    def __init__(self, message: str = "Malformed ciphertext or decryption failed."):
        super().__init__(message)
        self.code = "DATA_CORRUPTED"


class TransitEngine:
    def __init__(
        self,
        vault_manager: VaultManager,
        auth_manager: AuthManager,
        db: Optional[VaultDatabase] = None,
    ):
        self.vault_manager = vault_manager
        self.auth_manager = auth_manager
        self.db = db if db is not None else vault_manager.db

    def _enforce_key_access(
        self, key_name: str, token: str, action: str
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Enforce Named Key Access Control (Section 2.3):
        1. Verifies caller's session token.
        2. Retrieves key record from database.
        3. Checks if key exists AND caller_id == owner_id.
        4. If mismatched or not found: Refuses BEFORE touching any crypto operation,
           returns generic PERMISSION_DENIED error, and logs to audit_logs.
        """
        session = self.auth_manager.verify_session(token)
        clean_name = key_name.strip()

        key_record = self.db.get_transit_key(clean_name)
        caller_email = session["email"].lower().strip()

        if not key_record or key_record["owner_id"] != session["user_id"]:
            # Log denied attempt
            self.db.log_audit_event(
                requester_email=caller_email,
                target_resource=f"transit/{clean_name}",
                action=action.upper(),
                reason="PERMISSION_DENIED",
            )
            raise TransitKeyAccessDeniedError()

        return key_record, session

    # ==================================================================
    # Section 2.1: Named Key Management
    # ==================================================================
    def create_key(self, key_name: str, token: str) -> Dict[str, Any]:
        """
        Create a named symmetric AES-256 key for encryption/decryption (Section 2.1):
        1. Verifies caller token.
        2. Generates random 32-byte AES-256 key.
        3. Encrypts AES key with DEK in RAM.
        4. Saves record to transit_keys table (key_usage="ENCRYPT_DECRYPT").
        5. Returns key metadata (NEVER returns raw key material).
        """
        session = self.auth_manager.verify_session(token)
        clean_name = key_name.strip()

        if not clean_name:
            raise ValueError("Key name cannot be empty.")

        # Ensure Vault is unlocked
        self.vault_manager.require_unlocked()
        dek = self.vault_manager.get_dek()

        # Check if key_name already exists for this owner
        existing = self.db.get_transit_key(clean_name)
        if existing:
            if existing["owner_id"] == session["user_id"]:
                raise ValueError(f"Named key '{clean_name}' already exists.")
            else:
                # Disclose generic permission error if owned by someone else
                raise TransitKeyAccessDeniedError()

        # Generate random 32-byte AES-256 key
        raw_aes_key = secrets.token_bytes(32)

        # Encrypt raw AES key using DEK via AES-256-GCM
        nonce_b64, ct_b64, tag_b64 = encrypt_aes_gcm(dek, raw_aes_key)
        encrypted_key_material_b64 = pack_gcm_payload(nonce_b64, ct_b64, tag_b64)

        record = self.db.save_transit_key(
            key_name=clean_name,
            owner_id=session["user_id"],
            key_usage="ENCRYPT_DECRYPT",
            encrypted_key_material_b64=encrypted_key_material_b64,
        )

        return {
            "key_name": record["key_name"],
            "owner_email": session["email"],
            "key_usage": record["key_usage"],
            "created_at": record["created_at"],
        }

    def list_keys(self, token: str) -> List[Dict[str, Any]]:
        """List all named keys owned by caller (never exposing key material)."""
        session = self.auth_manager.verify_session(token)
        return self.db.list_transit_keys(session["user_id"])

    def revoke_key(self, key_name: str, token: str) -> bool:
        """Permanently delete a named key."""
        key_record, session = self._enforce_key_access(key_name, token, action="DELETE")
        return self.db.delete_transit_key(key_record["key_name"])

    # ==================================================================
    # Section 2.2: Encryption & Decryption APIs
    # ==================================================================
    def encrypt(self, key_name: str, plaintext_b64: str, token: str) -> str:
        """
        Encrypt plaintext using named key (Section 2.2):
        Output format: 'vault:<key_name>:<base64(nonce+ct+tag)>'
        """
        key_record, session = self._enforce_key_access(key_name, token, action="ENCRYPT")

        if key_record["key_usage"] != "ENCRYPT_DECRYPT":
            raise InvalidKeyUsageError("Key usage is SIGN_VERIFY, not ENCRYPT_DECRYPT.")

        # Ensure Vault is unlocked
        self.vault_manager.require_unlocked()
        dek = self.vault_manager.get_dek()

        # Decrypt raw AES key from DB using DEK
        try:
            n_b64, c_b64, t_b64 = unpack_gcm_payload(key_record["encrypted_key_material_b64"])
            raw_aes_key = decrypt_aes_gcm(dek, n_b64, c_b64, t_b64)
        except Exception as e:
            raise TransitDataCorruptedError("Failed to decrypt named key material.") from e

        # Decode client's plaintext
        try:
            plaintext = base64.b64decode(plaintext_b64)
        except Exception as e:
            raise ValueError(f"Invalid Base64 plaintext input: {e}") from e

        # Encrypt client's plaintext using raw AES key + fresh Nonce
        n2_b64, c2_b64, t2_b64 = encrypt_aes_gcm(raw_aes_key, plaintext)
        payload_b64 = pack_gcm_payload(n2_b64, c2_b64, t2_b64)

        return f"vault:{key_record['key_name']}:{payload_b64}"

    def decrypt(self, ciphertext_str: str, token: str) -> str:
        """
        Decrypt ciphertext of form 'vault:<key_name>:<base64(payload)>' (Section 2.2).
        Returns Base64 encoded plaintext.
        """
        if not ciphertext_str or not ciphertext_str.startswith("vault:"):
            raise TransitDataCorruptedError("Malformed ciphertext string (must start with 'vault:').")

        parts = ciphertext_str.split(":", 2)
        if len(parts) != 3:
            raise TransitDataCorruptedError("Malformed ciphertext string format.")

        key_name = parts[1]
        payload_b64 = parts[2]

        key_record, session = self._enforce_key_access(key_name, token, action="DECRYPT")

        if key_record["key_usage"] != "ENCRYPT_DECRYPT":
            raise InvalidKeyUsageError("Key usage is SIGN_VERIFY, not ENCRYPT_DECRYPT.")

        # Ensure Vault is unlocked
        self.vault_manager.require_unlocked()
        dek = self.vault_manager.get_dek()

        # Decrypt raw AES key using DEK
        try:
            n_b64, c_b64, t_b64 = unpack_gcm_payload(key_record["encrypted_key_material_b64"])
            raw_aes_key = decrypt_aes_gcm(dek, n_b64, c_b64, t_b64)
        except Exception as e:
            raise TransitDataCorruptedError("Failed to decrypt named key material.") from e

        # Unpack payload and decrypt plaintext
        try:
            n2_b64, c2_b64, t2_b64 = unpack_gcm_payload(payload_b64)
            plaintext = decrypt_aes_gcm(raw_aes_key, n2_b64, c2_b64, t2_b64)
            return base64.b64encode(plaintext).decode("utf-8")
        except VaultAuthenticationError:
            raise TransitDataCorruptedError("Ciphertext GCM tag mismatch or tampered data.")
        except Exception as e:
            raise TransitDataCorruptedError(f"Decryption failed: {e}") from e

    # ==================================================================
    # Section 2.4: Sign & Verify APIs
    # ==================================================================
    def create_signing_key(
        self, key_name: str, signing_algorithm: str, token: str
    ) -> Dict[str, Any]:
        """
        Create asymmetric signing key pair (ED25519 or RSA-2048) (Section 2.4):
        - Private key encrypted with DEK before disk persistence.
        - Public key stored Base64 encoded.
        """
        session = self.auth_manager.verify_session(token)
        clean_name = key_name.strip()
        algo = signing_algorithm.strip().upper()

        if algo not in ("ED25519", "RSA-2048", "RSA2048"):
            raise ValueError("Supported signing algorithms are 'ED25519' and 'RSA-2048'.")

        self.vault_manager.require_unlocked()
        dek = self.vault_manager.get_dek()

        # Generate key pair
        if algo == "ED25519":
            priv_key = ed25519.Ed25519PrivateKey.generate()
            pub_key = priv_key.public_key()
            algo_normalized = "ED25519"

            priv_bytes = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_bytes = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub_key = priv_key.public_key()
            algo_normalized = "RSA-2048"

            priv_bytes = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_bytes = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        # Encrypt private key bytes with DEK via AES-256-GCM
        n_b64, c_b64, t_b64 = encrypt_aes_gcm(dek, priv_bytes)
        encrypted_private_key_b64 = pack_gcm_payload(n_b64, c_b64, t_b64)
        public_key_b64 = base64.b64encode(pub_bytes).decode("utf-8")

        record = self.db.save_transit_key(
            key_name=clean_name,
            owner_id=session["user_id"],
            key_usage="SIGN_VERIFY",
            signing_algorithm=algo_normalized,
            encrypted_key_material_b64=encrypted_private_key_b64,
            public_key_b64=public_key_b64,
        )

        return {
            "key_name": record["key_name"],
            "owner_email": session["email"],
            "key_usage": "SIGN_VERIFY",
            "signing_algorithm": record["signing_algorithm"],
            "created_at": record["created_at"],
        }

    def _compute_digest(self, message_b64: str, message_type: str) -> bytes:
        """Compute message digest based on RAW or DIGEST type."""
        try:
            msg_bytes = base64.b64decode(message_b64)
        except Exception as e:
            raise ValueError(f"Invalid Base64 message input: {e}") from e

        m_type = message_type.strip().upper()
        if m_type == "RAW":
            # Hash message with SHA-256
            digest = hashlib.sha256(msg_bytes).digest()
            return digest
        elif m_type == "DIGEST":
            if len(msg_bytes) != 32:
                raise ValueError("DIGEST message_type requires a 32-byte precomputed hash.")
            return msg_bytes
        else:
            raise ValueError("message_type must be either 'RAW' or 'DIGEST'.")

    def sign(
        self, key_name: str, message_b64: str, message_type: str, token: str
    ) -> Dict[str, Any]:
        """
        Sign a message with named asymmetric private key (Section 2.4).
        """
        key_record, session = self._enforce_key_access(key_name, token, action="SIGN")

        if key_record["key_usage"] != "SIGN_VERIFY":
            raise InvalidKeyUsageError("Key usage is ENCRYPT_DECRYPT, not SIGN_VERIFY.")

        self.vault_manager.require_unlocked()
        dek = self.vault_manager.get_dek()

        # Decrypt private key PEM bytes using DEK
        try:
            n_b64, c_b64, t_b64 = unpack_gcm_payload(key_record["encrypted_key_material_b64"])
            priv_pem = decrypt_aes_gcm(dek, n_b64, c_b64, t_b64)
            priv_key = serialization.load_pem_private_key(priv_pem, password=None)
        except Exception as e:
            raise TransitDataCorruptedError("Failed to decrypt private key material.") from e

        digest = self._compute_digest(message_b64, message_type)
        algo = key_record["signing_algorithm"]

        # Sign using loaded private key
        if algo == "ED25519":
            # Ed25519 signs the raw message bytes directly if RAW, or raw digest
            raw_msg = base64.b64decode(message_b64)
            signature = priv_key.sign(raw_msg)
        else:
            # RSA-2048 PKCS1v15 with SHA256
            signature = priv_key.sign(
                digest,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

        signature_b64 = base64.b64encode(signature).decode("utf-8")

        return {
            "key_name": key_record["key_name"],
            "signature_b64": signature_b64,
            "signing_algorithm": algo,
        }

    def verify(
        self,
        key_name: str,
        message_b64: str,
        message_type: str,
        signature_b64: str,
        token: str,
    ) -> Dict[str, Any]:
        """
        Verify a signature using stored public key (Section 2.4).
        Returns structured result: { key_name, signature_valid: bool, signing_algorithm }.
        """
        # Verification requires valid session token & caller authorization
        key_record, session = self._enforce_key_access(key_name, token, action="VERIFY")

        if key_record["key_usage"] != "SIGN_VERIFY":
            raise InvalidKeyUsageError("Key usage is ENCRYPT_DECRYPT, not SIGN_VERIFY.")

        algo = key_record["signing_algorithm"]

        # Load public key
        try:
            pub_pem = base64.b64decode(key_record["public_key_b64"])
            pub_key = serialization.load_pem_public_key(pub_pem)
            signature = base64.b64decode(signature_b64)
        except Exception:
            return {
                "key_name": key_record["key_name"],
                "signature_valid": False,
                "signing_algorithm": algo,
            }

        try:
            if algo == "ED25519":
                raw_msg = base64.b64decode(message_b64)
                pub_key.verify(signature, raw_msg)
            else:
                digest = self._compute_digest(message_b64, message_type)
                pub_key.verify(
                    signature,
                    digest,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            is_valid = True
        except InvalidSignature:
            is_valid = False
        except Exception:
            is_valid = False

        return {
            "key_name": key_record["key_name"],
            "signature_valid": is_valid,
            "signing_algorithm": algo,
        }
