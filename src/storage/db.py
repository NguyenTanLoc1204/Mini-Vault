"""
Database Manager for Mini Vault using SQLite and schema.sql
"""

import os
import sqlite3
from typing import Dict, List, Optional, Tuple, Any

SCHEMA_FILE = os.path.join(os.path.dirname(__file__), "schema.sql")
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data",
    "vault.db"
)


class VaultDatabase:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._memory_conn: Optional[sqlite3.Connection] = None
        if db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:")
            self._memory_conn.row_factory = sqlite3.Row
            self._memory_conn.execute("PRAGMA foreign_keys = ON;")
        elif not db_path.startswith("file:"):
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        if self._memory_conn is not None:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        if not os.path.exists(SCHEMA_FILE):
            raise FileNotFoundError(f"Schema file not found at: {SCHEMA_FILE}")

        with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        conn = self.get_connection()
        conn.executescript(schema_sql)
        if self._memory_conn is None:
            conn.close()

    def close(self) -> None:
        if self._memory_conn:
            self._memory_conn.close()
            self._memory_conn = None

    # ------------------------------------------------------------------
    # Section 0.1: Vault Configuration Storage
    # ------------------------------------------------------------------
    def save_vault_config(
        self, kdf_salt_b64: str, encrypted_dek_b64: str, kdf: str = "argon2id", status: str = "locked"
    ) -> Dict[str, Any]:
        """Save or replace initial Vault configuration (ID=1)."""
        sql = """
        INSERT INTO vault_config (id, kdf, kdf_salt_b64, encrypted_dek_b64, status, updated_at)
        VALUES (1, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            kdf=excluded.kdf,
            kdf_salt_b64=excluded.kdf_salt_b64,
            encrypted_dek_b64=excluded.encrypted_dek_b64,
            status=excluded.status,
            updated_at=CURRENT_TIMESTAMP;
        """
        conn = self.get_connection()
        conn.execute(sql, (kdf, kdf_salt_b64, encrypted_dek_b64, status))
        conn.commit()
        if self._memory_conn is None:
            conn.close()
        return self.get_vault_config()  # type: ignore

    def get_vault_config(self) -> Optional[Dict[str, Any]]:
        """Retrieve current Vault configuration."""
        sql = "SELECT id, kdf, kdf_salt_b64, encrypted_dek_b64, status, created_at, updated_at FROM vault_config WHERE id = 1;"
        conn = self.get_connection()
        row = conn.execute(sql).fetchone()
        result = dict(row) if row else None
        if self._memory_conn is None:
            conn.close()
        return result

    def update_vault_status(self, status: str) -> bool:
        """Update Vault status ('locked' / 'unlocked')."""
        if status not in ("locked", "unlocked"):
            raise ValueError("Status must be either 'locked' or 'unlocked'")
        sql = "UPDATE vault_config SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1;"
        conn = self.get_connection()
        cursor = conn.execute(sql, (status,))
        conn.commit()
        updated = cursor.rowcount > 0
        if self._memory_conn is None:
            conn.close()
        return updated

    # ------------------------------------------------------------------
    # Section 0.2: User Identity & Authentication Storage
    # ------------------------------------------------------------------
    def create_user(self, email: str, password_hash: str) -> Dict[str, Any]:
        """Create a new user entry."""
        sql = "INSERT INTO users (email, password_hash) VALUES (?, ?);"
        conn = self.get_connection()
        conn.execute(sql, (email.lower().strip(), password_hash))
        conn.commit()
        if self._memory_conn is None:
            conn.close()
        return self.get_user(email)  # type: ignore

    def get_user(self, email: str) -> Optional[Dict[str, Any]]:
        """Fetch user by email."""
        sql = "SELECT id, email, password_hash, failed_attempts, lockout_until, created_at FROM users WHERE email = ?;"
        conn = self.get_connection()
        row = conn.execute(sql, (email.lower().strip(),)).fetchone()
        result = dict(row) if row else None
        if self._memory_conn is None:
            conn.close()
        return result

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Fetch user by ID."""
        sql = "SELECT id, email, password_hash, failed_attempts, lockout_until, created_at FROM users WHERE id = ?;"
        conn = self.get_connection()
        row = conn.execute(sql, (user_id,)).fetchone()
        result = dict(row) if row else None
        if self._memory_conn is None:
            conn.close()
        return result

    def update_user_failed_attempts(
        self, email: str, failed_attempts: int, lockout_until: Optional[str] = None
    ) -> bool:
        """Update failed login attempts and optional lockout timestamp."""
        sql = "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE email = ?;"
        conn = self.get_connection()
        cursor = conn.execute(sql, (failed_attempts, lockout_until, email.lower().strip()))
        conn.commit()
        updated = cursor.rowcount > 0
        if self._memory_conn is None:
            conn.close()
        return updated

    def reset_user_lockout(self, email: str) -> bool:
        """Reset failed attempts and clear lockout timestamp upon successful login."""
        sql = "UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE email = ?;"
        conn = self.get_connection()
        cursor = conn.execute(sql, (email.lower().strip(),))
        conn.commit()
        updated = cursor.rowcount > 0
        if self._memory_conn is None:
            conn.close()
        return updated

    def delete_user(self, user_id: int) -> bool:
        """Delete user by ID (triggers CASCADE deletion for kv_secrets and transit_keys)."""
        sql = "DELETE FROM users WHERE id = ?;"
        conn = self.get_connection()
        cursor = conn.execute(sql, (user_id,))
        conn.commit()
        updated = cursor.rowcount > 0
        if self._memory_conn is None:
            conn.close()
        return updated

    def delete_user_by_email(self, email: str) -> bool:
        """Delete user by email (triggers CASCADE deletion for kv_secrets and transit_keys)."""
        sql = "DELETE FROM users WHERE email = ?;"
        conn = self.get_connection()
        cursor = conn.execute(sql, (email.lower().strip(),))
        conn.commit()
        updated = cursor.rowcount > 0
        if self._memory_conn is None:
            conn.close()
        return updated

    # ------------------------------------------------------------------
    # Feature 1: KV Engine Storage (Encrypted-at-Rest)
    # ------------------------------------------------------------------
    def put_kv_secret(
        self, path: str, owner_id: int, nonce_b64: str, ciphertext_b64: str, tag_b64: str
    ) -> Dict[str, Any]:
        """Write or update encrypted KV secret."""
        sql = """
        INSERT INTO kv_secrets (path, owner_id, nonce_b64, ciphertext_b64, tag_b64, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(path) DO UPDATE SET
            owner_id=excluded.owner_id,
            nonce_b64=excluded.nonce_b64,
            ciphertext_b64=excluded.ciphertext_b64,
            tag_b64=excluded.tag_b64,
            updated_at=CURRENT_TIMESTAMP;
        """
        clean_path = path.strip()
        conn = self.get_connection()
        conn.execute(sql, (clean_path, owner_id, nonce_b64, ciphertext_b64, tag_b64))
        conn.commit()
        if self._memory_conn is None:
            conn.close()
        return self.get_kv_secret(clean_path)  # type: ignore

    def get_kv_secret(self, path: str) -> Optional[Dict[str, Any]]:
        """Retrieve KV secret metadata, owner_id, owner_email, and ciphertext."""
        sql = """
        SELECT k.path, k.owner_id, u.email AS owner_email, k.nonce_b64, k.ciphertext_b64, k.tag_b64, k.created_at, k.updated_at
        FROM kv_secrets k
        JOIN users u ON k.owner_id = u.id
        WHERE k.path = ?;
        """
        conn = self.get_connection()
        row = conn.execute(sql, (path.strip(),)).fetchone()
        result = dict(row) if row else None
        if self._memory_conn is None:
            conn.close()
        return result

    def delete_kv_secret(self, path: str) -> bool:
        """Permanently delete a KV secret by path."""
        sql = "DELETE FROM kv_secrets WHERE path = ?;"
        conn = self.get_connection()
        cursor = conn.execute(sql, (path.strip(),))
        conn.commit()
        updated = cursor.rowcount > 0
        if self._memory_conn is None:
            conn.close()
        return updated

    # ------------------------------------------------------------------
    # Feature 2: Transit Engine Named Keys Storage
    # ------------------------------------------------------------------
    def save_transit_key(
        self,
        key_name: str,
        owner_id: int,
        key_usage: str,
        encrypted_key_material_b64: str,
        signing_algorithm: Optional[str] = None,
        public_key_b64: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Save a named key for Transit Engine (Symmetric or Asymmetric)."""
        sql = """
        INSERT INTO transit_keys (key_name, owner_id, key_usage, signing_algorithm, encrypted_key_material_b64, public_key_b64)
        VALUES (?, ?, ?, ?, ?, ?);
        """
        clean_name = key_name.strip()
        conn = self.get_connection()
        conn.execute(
            sql,
            (
                clean_name,
                owner_id,
                key_usage,
                signing_algorithm,
                encrypted_key_material_b64,
                public_key_b64,
            ),
        )
        conn.commit()
        if self._memory_conn is None:
            conn.close()
        return self.get_transit_key(clean_name)  # type: ignore

    def get_transit_key(self, key_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve named key record with joined owner_email."""
        sql = """
        SELECT t.key_name, t.owner_id, u.email AS owner_email, t.key_usage, t.signing_algorithm,
               t.encrypted_key_material_b64, t.public_key_b64, t.created_at
        FROM transit_keys t
        JOIN users u ON t.owner_id = u.id
        WHERE t.key_name = ?;
        """
        conn = self.get_connection()
        row = conn.execute(sql, (key_name.strip(),)).fetchone()
        result = dict(row) if row else None
        if self._memory_conn is None:
            conn.close()
        return result

    def list_transit_keys(self, owner_id: int) -> List[Dict[str, Any]]:
        """List all named key metadata owned by a specific user ID (never exposing plaintext keys)."""
        sql = """
        SELECT t.key_name, t.owner_id, u.email AS owner_email, t.key_usage, t.signing_algorithm, t.created_at
        FROM transit_keys t
        JOIN users u ON t.owner_id = u.id
        WHERE t.owner_id = ?;
        """
        conn = self.get_connection()
        rows = conn.execute(sql, (owner_id,)).fetchall()
        result = [dict(r) for r in rows]
        if self._memory_conn is None:
            conn.close()
        return result

    def delete_transit_key(self, key_name: str) -> bool:
        """Revoke / permanently delete a named key."""
        sql = "DELETE FROM transit_keys WHERE key_name = ?;"
        conn = self.get_connection()
        cursor = conn.execute(sql, (key_name.strip(),))
        conn.commit()
        updated = cursor.rowcount > 0
        if self._memory_conn is None:
            conn.close()
        return updated

    # ------------------------------------------------------------------
    # Audit Logging (Sections 1.2 & 2.3)
    # ------------------------------------------------------------------
    def log_audit_event(
        self, requester_email: str, target_resource: str, action: str, reason: str
    ) -> int:
        """Record an access denial or security event."""
        sql = """
        INSERT INTO audit_logs (requester_email, target_resource, action, reason)
        VALUES (?, ?, ?, ?);
        """
        conn = self.get_connection()
        cursor = conn.execute(
            sql, (requester_email.lower().strip(), target_resource, action, reason)
        )
        conn.commit()
        last_id = cursor.lastrowid
        if self._memory_conn is None:
            conn.close()
        return last_id

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch audit log entries."""
        sql = "SELECT id, timestamp, requester_email, target_resource, action, reason FROM audit_logs ORDER BY id DESC LIMIT ?;"
        conn = self.get_connection()
        rows = conn.execute(sql, (limit,)).fetchall()
        result = [dict(r) for r in rows]
        if self._memory_conn is None:
            conn.close()
        return result
