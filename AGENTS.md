# Agent Operating Guide - Mini Vault

## Scope And Precedence

This document provides project context, architecture guidelines, and operational conventions for AI coding agents (Codex and Antigravity) working in the **Mini Vault** repository.

- Direct user instructions for the active task take precedence over this document.
- Follow instructions in local `SKILL.md` files for specific domain workflows.
- Keep all modifications scoped strictly to requested requirements without over-engineering.

---

## Project Snapshot

- **Project Name**: Mini Vault (Computer Security Course Assignment 1)
- **Primary Objective**: Build a secure key-value (KV) storage engine and Encryption/Signing as a Service (Transit) engine modeled after HashiCorp Vault and AWS KMS.
- **Language**: Python 3
- **Storage**: SQLite 3 (`sqlite3` built-in) via DDL schema `src/storage/schema.sql`
- **Crypto Libraries**: `cryptography`, `argon2-cffi`, `bcrypt`, `secrets`
- **API Framework**: FastAPI / Flask (encouraged) or CLI

---

## Repository Structure

```text
.
├── AGENTS.md                 # Agent operating guide & project context
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

---

## Commands

- **Run Tests**:
  ```bash
  ./venv/bin/python -m unittest discover tests
  # Or target specific module test:
  ./venv/bin/python -m unittest tests/test_storage.py
  ./venv/bin/python -m unittest tests/test_core.py
  ./venv/bin/python -m unittest tests/test_auth.py
  ./venv/bin/python -m unittest tests/test_kv.py
  ./venv/bin/python -m unittest tests/test_transit.py
  ```
- **Run Application**:
  ```bash
  ./venv/bin/python main.py
  ```

---

## Architecture & Security Principles

1. **Envelope Encryption (Two-Layer Keys)**:
   - **Master Key**: Derived dynamically from `Master Passphrase + Salt` using **Argon2id** (`t=3, m=64MB, p=4`). Never stored on disk.
   - **Data Encryption Key (DEK)**: Random 256-bit AES key created at initialization, stored encrypted on disk (`encrypted_dek_b64`), decrypted into RAM upon vault unlock.

2. **Single Source of Truth**:
   - The vault is `unlocked` **IF AND ONLY IF** the decrypted DEK is actively held in RAM.
   - On process startup or restart, the system defaults to `locked`.

3. **Data Contracts & Schemas**:
   - **`vault_config`**: Stores KDF settings, salt, encrypted DEK, and status (`locked`/`unlocked`).
   - **`users`**: Stores `id` (PK AUTOINCREMENT), `email` (UNIQUE), `password_hash`, `failed_attempts`, `lockout_until`.
   - **`kv_secrets`**: Encrypted at rest via AES-256-GCM with fresh nonces per write (`path`, `owner_id` FK -> `users(id)`).
   - **`transit_keys`**: Named keys for symmetric encryption (`ENCRYPT_DECRYPT`) and asymmetric signing (`SIGN_VERIFY`). Private key material is encrypted with DEK and never exposed plaintext via APIs.
   - **`audit_logs`**: Logs all access denial attempts with timestamps, requester email, target resource, and reasons.

---

## Code Quality & Safety Rules

- **Never Log or Expose Secrets**: Never log plaintext passphrases, raw DEKs, private keys, or session tokens.
- **Parametrized SQL Queries**: Always use `?` placeholders in SQLite queries to prevent SQL injection vulnerabilities.
- **Foreign Key Integrity**: Always enable `PRAGMA foreign_keys = ON;` in SQLite connections.
- **Fail-Closed Access Control**: Deny cross-user access attempts immediately and log access denials to `audit_logs`.

---

## Git Conventions

- Never stage `.env` files, `.db` binary databases, private keys, or `__pycache__` directories.
- Always run preflight checks (`git status --short --branch`, `git diff --cached`) before committing.
- Use Conventional Commit prefixes (e.g. `feat:`, `fix:`, `test:`, `docs:`).
