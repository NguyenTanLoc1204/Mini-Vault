"""
Unit tests for Mini Vault Main Launcher (main.py)
"""

import unittest
from main import MiniVaultCLI


class TestMainLauncher(unittest.TestCase):
    def setUp(self):
        self.cli = MiniVaultCLI(":memory:")

    def tearDown(self):
        self.cli.db.close()

    def test_cli_initialization(self):
        self.assertIsNotNone(self.cli.db)
        self.assertIsNotNone(self.cli.vault_mgr)
        self.assertIsNotNone(self.cli.auth_mgr)
        self.assertIsNotNone(self.cli.kv_engine)
        self.assertIsNotNone(self.cli.transit_engine)
        self.assertFalse(self.cli.vault_mgr.is_unlocked)
        self.assertIsNone(self.cli.current_user)

    def test_require_login_behavior(self):
        # Without login returns None
        self.assertIsNone(self.cli.require_login())

        # Set fake token and user
        self.cli.current_token = "fake_token"
        self.cli.current_user = {"id": 1, "email": "test@example.com"}
        self.assertEqual(self.cli.require_login(), "fake_token")


if __name__ == "__main__":
    unittest.main()
