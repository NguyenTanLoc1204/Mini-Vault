# Mini Vault - Secure Storage & Encryption/Signing as a Service

Mini Vault is a security system built for **Assignment 1 - Computer Security Course**, implementing a Secure Storage Key-Value (KV) engine and an Encryption & Signing as a Service (Transit) engine.

## 📁 Project Structure

```
.
├── README.md
├── requirements.txt
├── .env.example
├── main.py
├── src/
│   ├── core/         # Master Passphrase, Vault init/unlock, DEK handling
│   ├── auth/         # User registration, login, session token & lockout
│   ├── kv/           # Feature 1: Secure Storage (KV Engine)
│   ├── transit/      # Feature 2: Encryption & Signing as a Service (Transit Engine)
│   └── storage/      # Disk storage I/O
├── tests/            # Test suite (pytest)
├── data/
│   ├── samples/      # Test samples & exported ciphertexts
│   └── logs/         # System & security audit logs
└── docs/
    └── report/       # Assignment report (PDF)
```

## 🚀 Setup & Execution

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 3. Run Mini Vault
```bash
python main.py
```
