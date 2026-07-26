-- Mini Vault Database Schema

-- 1. Vault Config Table (Section 0.1)
CREATE TABLE IF NOT EXISTS vault_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    kdf TEXT NOT NULL DEFAULT 'argon2id',
    kdf_salt_b64 TEXT NOT NULL,
    encrypted_dek_b64 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('locked', 'unlocked')) DEFAULT 'locked',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Users Table (Section 0.2)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lockout_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. KV Secrets Table (Feature 1 - Section 1.1 & 1.2)
CREATE TABLE IF NOT EXISTS kv_secrets (
    path TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    tag_b64 TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 4. Transit Engine Named Keys Table (Feature 2 - Section 2.1, 2.2, 2.4)
CREATE TABLE IF NOT EXISTS transit_keys (
    key_name TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    key_usage TEXT NOT NULL CHECK (key_usage IN ('ENCRYPT_DECRYPT', 'SIGN_VERIFY')),
    signing_algorithm TEXT NULL,
    encrypted_key_material_b64 TEXT NOT NULL,
    public_key_b64 TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 5. Audit Logs Table (Section 1.2 & 2.3 - Access Denial Logging)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    requester_email TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_kv_owner ON kv_secrets(owner_id);
CREATE INDEX IF NOT EXISTS idx_transit_owner ON transit_keys(owner_id);
