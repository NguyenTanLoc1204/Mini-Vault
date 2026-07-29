"""
Mini Vault - Interactive CLI Application Launcher & Menu System
Computer Security Course - Assignment 1
"""

import base64
import getpass
import json
import os
import io
import sys
from typing import Optional, Dict, Any

from src.storage import VaultDatabase
from src.core import (
    VaultManager,
    VaultLockedError,
    VaultAlreadyInitializedError,
    InvalidPassphraseError,
    VaultAuthenticationError,
)
from src.auth import (
    SessionManager,
    AuthManager,
    UserAlreadyExistsError,
    UserNotFoundError,
    InvalidCredentialsError,
    AccountLockedError,
    InvalidSessionTokenError,
    SessionExpiredError,
)
from src.kv import (
    KVEngine,
    KVPathAccessDeniedError,
    KVNotFoundError,
    KVDataCorruptedError,
    KVInvalidPathError,
)
from src.transit import (
    TransitEngine,
    TransitKeyAccessDeniedError,
    TransitKeyNotFoundError,
    InvalidKeyUsageError,
    TransitDataCorruptedError,
)


class MiniVaultCLI:
    def __init__(self, db_path: str = "data/vault.db"):
        dir_name = os.path.dirname(db_path)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        self.db = VaultDatabase(db_path)
        self.vault_mgr = VaultManager(self.db)
        self.session_mgr = SessionManager(default_ttl_minutes=30)
        self.auth_mgr = AuthManager(db=self.db, session_manager=self.session_mgr)
        self.kv_engine = KVEngine(vault_manager=self.vault_mgr, auth_manager=self.auth_mgr, db=self.db)
        self.transit_engine = TransitEngine(vault_manager=self.vault_mgr, auth_manager=self.auth_mgr, db=self.db)

        self.current_token: Optional[str] = None
        self.current_user: Optional[Dict[str, Any]] = None

    def print_banner(self):
        print("\n" + "=" * 60)
        print("                🔐 MINI VAULT SECURITY SYSTEM")
        print("          Secure Storage (KV) & Transit Engine (KMS)")
        print("=" * 60)
        vault_status = "🔓 UNLOCKED" if self.vault_mgr.is_unlocked else "🔒 LOCKED"
        if not self.vault_mgr.is_initialized():
            vault_status = "⚠️ NOT INITIALIZED"

        user_status = (
            f"👤 Logged in as: {self.current_user['email']}"
            if self.current_user
            else "👤 Not logged in"
        )

        print(f" Status: Vault [{vault_status}]  |  {user_status}")
        print("-" * 60)

    def prompt_passphrase(self, prompt: str = "Enter Master Passphrase: ") -> str:
        """Prompt for passphrase securely without echo if in terminal."""
        try:
            return getpass.getpass(prompt)
        except (AttributeError, io.UnsupportedOperation):
            return input(prompt)

    # ------------------------------------------------------------------
    # Vault Master Controls
    # ------------------------------------------------------------------
    def do_init_vault(self):
        print("\n--- Initialize Vault ---")
        if self.vault_mgr.is_initialized():
            print("❌ Vault is already initialized.")
            return

        passphrase = self.prompt_passphrase("Create Master Passphrase (min 8 chars): ")
        confirm = self.prompt_passphrase("Confirm Master Passphrase: ")
        if passphrase != confirm:
            print("❌ Passphrases do not match.")
            return

        try:
            self.vault_mgr.init_vault(passphrase)
            print("✅ Vault initialized and unlocked successfully!")
        except Exception as e:
            print(f"❌ Initialization failed: {e}")

    def do_unlock_vault(self):
        print("\n--- Unlock Vault ---")
        if self.vault_mgr.is_unlocked:
            print("ℹ️ Vault is already unlocked.")
            return

        passphrase = self.prompt_passphrase("Enter Master Passphrase: ")
        try:
            self.vault_mgr.unlock_vault(passphrase)
            print("✅ Vault unlocked successfully! DEK loaded into RAM.")
        except InvalidPassphraseError as e:
            print(f"❌ {e}")
        except Exception as e:
            print(f"❌ Unlock failed: {e}")

    def do_lock_vault(self):
        print("\n--- Lock Vault ---")
        self.vault_mgr.lock_vault()
        print("🔒 Vault locked. DEK wiped from RAM.")

    # ------------------------------------------------------------------
    # User Identity & Auth Controls
    # ------------------------------------------------------------------
    def do_register_user(self):
        print("\n--- Register User ---")
        email = input("Enter email: ").strip()
        passphrase = self.prompt_passphrase("Enter passphrase: ")
        confirm = self.prompt_passphrase("Confirm passphrase: ")

        try:
            user = self.auth_mgr.register(email, passphrase, confirm)
            print(f"✅ User '{user['email']}' registered successfully (ID: {user['id']})!")
        except UserAlreadyExistsError as e:
            print(f"❌ {e}")
        except Exception as e:
            print(f"❌ Registration failed: {e}")

    def do_login_user(self):
        print("\n--- Login User ---")
        email = input("Enter email: ").strip()
        passphrase = self.prompt_passphrase("Enter passphrase: ")

        try:
            res = self.auth_mgr.login(email, passphrase)
            self.current_token = res["token"]
            self.current_user = res["user"]
            print(f"✅ Login successful! Session token issued (expires: {res['expires_at']}).")
        except AccountLockedError as e:
            print(f"⛔ ACCOUNT LOCKED: {e}")
        except (UserNotFoundError, InvalidCredentialsError) as e:
            print(f"❌ {e}")
        except Exception as e:
            print(f"❌ Login failed: {e}")

    def do_logout_user(self):
        print("\n--- Logout User ---")
        if self.current_token:
            self.auth_mgr.logout(self.current_token)
            self.current_token = None
            self.current_user = None
            print("👋 Logged out successfully.")
        else:
            print("ℹ️ No active session.")

    def require_login(self) -> Optional[str]:
        if not self.current_token or not self.current_user:
            print("❌ Please log in first.")
            return None
        return self.current_token

    # ------------------------------------------------------------------
    # Feature 1: KV Engine Controls
    # ------------------------------------------------------------------
    def do_kv_write(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- Write KV Secret ---")
        default_path = f"secret/{self.current_user['email']}/my-secret"
        path = input(f"Enter secret path [{default_path}]: ").strip() or default_path
        payload_str = input("Enter JSON payload (e.g. {\"api_key\":\"12345\"}): ").strip()

        try:
            data = json.loads(payload_str)
            res = self.kv_engine.write_secret(path, data, token)
            print(f"✅ Secret stored successfully at '{res['path']}'!")
        except json.JSONDecodeError:
            print("❌ Invalid JSON string.")
        except (KVPathAccessDeniedError, VaultLockedError, Exception) as e:
            print(f"❌ {e}")

    def do_kv_read(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- Read KV Secret ---")
        default_path = f"secret/{self.current_user['email']}/my-secret"
        path = input(f"Enter secret path [{default_path}]: ").strip() or default_path

        try:
            data = self.kv_engine.read_secret(path, token)
            print(f"✅ Decrypted Secret Content:\n{json.dumps(data, indent=2)}")
        except (KVPathAccessDeniedError, KVNotFoundError, KVDataCorruptedError, VaultLockedError, Exception) as e:
            print(f"❌ {e}")

    def do_kv_delete(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- Delete KV Secret ---")
        path = input("Enter secret path to delete: ").strip()

        try:
            deleted = self.kv_engine.delete_secret(path, token)
            if deleted:
                print("✅ Secret deleted successfully.")
            else:
                print("ℹ️ Secret path not found or already deleted.")
        except (KVPathAccessDeniedError, Exception) as e:
            print(f"❌ {e}")

    # ------------------------------------------------------------------
    # Feature 2: Transit Engine Controls
    # ------------------------------------------------------------------
    def do_transit_create_key(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- Create Transit Symmetric Encryption Key ---")
        key_name = input("Enter key name (e.g. app-db-key): ").strip()
        try:
            res = self.transit_engine.create_key(key_name, token)
            print(f"✅ Key '{res['key_name']}' ({res['key_usage']}) created successfully!")
        except Exception as e:
            print(f"❌ Key creation failed: {e}")

    def do_transit_encrypt(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- Transit Encrypt ---")
        key_name = input("Enter key name: ").strip()
        plaintext = input("Enter plaintext string to encrypt: ").strip()
        plaintext_b64 = base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")

        try:
            ciphertext = self.transit_engine.encrypt(key_name, plaintext_b64, token)
            print(f"✅ Ciphertext Result:\n{ciphertext}")
        except (TransitKeyAccessDeniedError, InvalidKeyUsageError, VaultLockedError, Exception) as e:
            print(f"❌ Encryption failed: {e}")

    def do_transit_decrypt(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- Transit Decrypt ---")
        ciphertext_str = input("Enter ciphertext string (vault:<key_name>:...): ").strip()

        try:
            plaintext_b64 = self.transit_engine.decrypt(ciphertext_str, token)
            plaintext = base64.b64decode(plaintext_b64).decode("utf-8")
            print(f"✅ Decrypted Plaintext Result:\n{plaintext}")
        except (TransitKeyAccessDeniedError, InvalidKeyUsageError, TransitDataCorruptedError, VaultLockedError, Exception) as e:
            print(f"❌ Decryption failed: {e}")

    def do_transit_create_sign_key(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- Create Transit Asymmetric Signing Key ---")
        key_name = input("Enter key name: ").strip()
        print("Supported algorithms: 1. ED25519 (Recommended)  2. RSA-2048")
        choice = input("Select algorithm [1/2]: ").strip()
        algo = "RSA-2048" if choice == "2" else "ED25519"

        try:
            res = self.transit_engine.create_signing_key(key_name, algo, token)
            print(f"✅ Signing key '{res['key_name']}' ({res['signing_algorithm']}) created successfully!")
        except Exception as e:
            print(f"❌ Key creation failed: {e}")

    def do_transit_sign(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- Transit Sign Message ---")
        key_name = input("Enter signing key name: ").strip()
        msg_text = input("Enter message string: ").strip()
        msg_b64 = base64.b64encode(msg_text.encode("utf-8")).decode("utf-8")

        try:
            res = self.transit_engine.sign(key_name, msg_b64, "RAW", token)
            print(f"✅ Signature Result (Base64):\n{res['signature_b64']}")
        except Exception as e:
            print(f"❌ Signing failed: {e}")

    def do_transit_verify(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- Transit Verify Signature ---")
        key_name = input("Enter signing key name: ").strip()
        msg_text = input("Enter message string: ").strip()
        msg_b64 = base64.b64encode(msg_text.encode("utf-8")).decode("utf-8")
        sig_b64 = input("Enter Base64 signature string: ").strip()

        try:
            res = self.transit_engine.verify(key_name, msg_b64, "RAW", sig_b64, token)
            if res["signature_valid"]:
                print(f"✅ SIGNATURE VALID! (Algorithm: {res['signing_algorithm']})")
            else:
                print("❌ SIGNATURE INVALID! Message or signature has been tampered with.")
        except Exception as e:
            print(f"❌ Verification failed: {e}")

    def do_transit_list(self):
        token = self.require_login()
        if not token:
            return

        print("\n--- My Transit Keys ---")
        keys = self.transit_engine.list_keys(token)
        if not keys:
            print("ℹ️ No transit keys found.")
            return

        for k in keys:
            algo_info = f" ({k['signing_algorithm']})" if k.get("signing_algorithm") else ""
            print(f" • Key: {k['key_name']:<20} | Usage: {k['key_usage']}{algo_info} | Created: {k['created_at']}")

    def do_view_audit_logs(self):
        print("\n--- Security Audit Logs ---")
        logs = self.db.get_audit_logs(limit=20)
        if not logs:
            print("ℹ️ No audit logs recorded.")
            return

        for l in logs:
            print(f" [{l['timestamp']}] Requester: {l['requester_email']:<20} | Resource: {l['target_resource']:<25} | Action: {l['action']} | Reason: {l['reason']}")

    def run(self):
        while True:
            self.print_banner()
            print(" [Vault]   1. Init Vault   2. Unlock Vault   3. Lock Vault")
            print(" [Auth]    4. Register     5. Login          6. Logout")
            print(" [KV]      7. Write Secret 8. Read Secret    9. Delete Secret")
            print(" [Transit] 10. Create Enc Key  11. Encrypt    12. Decrypt")
            print("           13. Create Sign Key 14. Sign       15. Verify  16. List Keys")
            print(" [Audit]   17. View Audit Logs")
            print("           0. Exit")
            print("-" * 60)

            choice = input("Select option [0-17]: ").strip()

            if choice == "0":
                print("Goodbye!")
                break
            elif choice == "1":
                self.do_init_vault()
            elif choice == "2":
                self.do_unlock_vault()
            elif choice == "3":
                self.do_lock_vault()
            elif choice == "4":
                self.do_register_user()
            elif choice == "5":
                self.do_login_user()
            elif choice == "6":
                self.do_logout_user()
            elif choice == "7":
                self.do_kv_write()
            elif choice == "8":
                self.do_kv_read()
            elif choice == "9":
                self.do_kv_delete()
            elif choice == "10":
                self.do_transit_create_key()
            elif choice == "11":
                self.do_transit_encrypt()
            elif choice == "12":
                self.do_transit_decrypt()
            elif choice == "13":
                self.do_transit_create_sign_key()
            elif choice == "14":
                self.do_transit_sign()
            elif choice == "15":
                self.do_transit_verify()
            elif choice == "16":
                self.do_transit_list()
            elif choice == "17":
                self.do_view_audit_logs()
            else:
                print("❌ Invalid option. Please enter a number between 0 and 17.")

            input("\nPress Enter to continue...")


if __name__ == "__main__":
    cli = MiniVaultCLI()
    cli.run()
