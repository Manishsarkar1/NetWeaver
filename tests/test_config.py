import unittest

from vanta_core.config import RuntimeConfig, build_user_store


class ConfigTests(unittest.TestCase):
    def test_build_user_store_uses_runtime_credentials(self):
        config = RuntimeConfig(
            secret_key="secret",
            admin_username="operator",
            admin_password="strong-pass",
        )

        users = build_user_store(lambda password: f"hashed::{password}", config=config)

        self.assertEqual(
            users,
            {
                "operator": {
                    "password": "hashed::strong-pass",
                    "role": "admin",
                }
            },
        )


if __name__ == "__main__":
    unittest.main()
