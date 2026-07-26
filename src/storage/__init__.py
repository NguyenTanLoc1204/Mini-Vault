"""
Storage Module: Read/Write encrypted data to disk using SQLite
"""

from src.storage.db import VaultDatabase, DEFAULT_DB_PATH

__all__ = ["VaultDatabase", "DEFAULT_DB_PATH"]
