# Mini Vault - Secure Storage & Encryption/Signing as a Service

Mini Vault is a security system built for **Assignment 1 - Computer Security Course**, implementing a Secure Storage Key-Value (KV) engine and an Encryption & Signing as a Service (Transit) engine modeled after HashiCorp Vault and AWS KMS.

## 📁 Project Structure

```text
.
├── AGENTS.md                 # Agent operating guide & project guidelines
├── README.md                 # Project README and execution guide
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variables template
├── .gitignore                # Git ignore rules for bytecode, secrets, and SQLite DBs
├── main.py                   # Main entry point launcher
├── src/                      # Source package
│   ├── core/                # Section 0.1: Master Passphrase, Argon2id KDF, DEK management
│   ├── auth/                # Section 0.2: User identity, password hashing, session tokens, lockout
│   ├── kv/                  # Feature 1: KV Engine (AEAD AES-256-GCM, ownership ACL)
│   ├── transit/             # Feature 2: Transit Engine (Encrypt/Decrypt, Sign/Verify)
│   └── storage/             # SQLite Database Manager (db.py & schema.sql)
├── tests/                    # Unit and integration test suite
├── data/                     # Local data directory (ignored in git)
└── docs/
    └── report/              # Final report output path
```

## 🚀 Setup & Execution

### 1. Create Virtual Environment & Install Dependencies
```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 3. Run Test Suite
```bash
./venv/bin/python -m unittest discover tests
```

### 4. Run Mini Vault Application
```bash
./venv/bin/python main.py
```

---

## 🛡️ Completed Modules Status

- [x] **Core Storage Engine (`src/storage/`)**: SQLite database engine (`db.py`) executing `schema.sql` (`vault_config`, `users`, `kv_secrets`, `transit_keys`, `audit_logs`).
- [x] **Feature 0.1 Vault Init & Unlock (`src/core/`)**: Argon2id KDF key derivation ($m=64\text{MB}, t=3, p=4$), AES-256-GCM DEK envelope encryption, and in-memory key isolation.
- [x] **Feature 0.2 User Authentication (`src/auth/`)**: User registration, Bcrypt hashing, 256-bit session tokens (30-min TTL), and mandatory 5-fail 5-min account lockout.
- [x] **Feature 1 Secure Storage (`src/kv/`)**: AEAD AES-256-GCM encrypted-at-rest secrets & path-based ownership ACL (`secret/<owner_email>/...`).
- [x] **Feature 2 Transit Engine (`src/transit/`)**: Named key management (AES-256), Encrypt/Decrypt API (`vault:<key_name>:...`), Sign & Verify API (ED25519 & RSA-2048), and cross-user ACL.
