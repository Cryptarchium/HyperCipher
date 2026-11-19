"""
Tests for pyouro.crypto.vault — AES-GCM encryption, HKDF key derivation,
and integrity hashing functions.
"""
import os
import secrets
import hashlib
import tempfile
import unittest
from pathlib import Path


class TestVaultEncryptDecrypt(unittest.TestCase):
    """Tests the encrypt_vault / decrypt_vault round-trip."""

    def setUp(self):
        from pyouro.crypto.vault import encrypt_vault, decrypt_vault
        self.encrypt = encrypt_vault
        self.decrypt = decrypt_vault
        self.key = secrets.token_bytes(32)  # 256-bit AES key

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data can be decrypted back to the original."""
        data = {"api_key": "super_secret_123", "db_password": "hunter2"}
        encrypted = self.encrypt(data, self.key)
        decrypted = self.decrypt(encrypted, self.key)
        self.assertEqual(decrypted, data)

    def test_encrypt_produces_different_ciphertext_each_time(self):
        """Two encryptions of the same data must produce different ciphertext (random nonce)."""
        data = {"key": "value"}
        enc1 = self.encrypt(data, self.key)
        enc2 = self.encrypt(data, self.key)
        self.assertNotEqual(enc1, enc2)

    def test_decrypt_with_wrong_key_raises(self):
        """Decryption with a wrong key must raise ValueError (AES-GCM auth failure)."""
        data = {"secret": "password"}
        encrypted = self.encrypt(data, self.key)
        wrong_key = secrets.token_bytes(32)
        with self.assertRaises(ValueError):
            self.decrypt(encrypted, wrong_key)

    def test_decrypt_tampered_ciphertext_raises(self):
        """Any tampering with the ciphertext must raise ValueError."""
        data = {"secret": "test"}
        encrypted = bytearray(self.encrypt(data, self.key))
        # Flip a bit in the ciphertext portion (after 12-byte nonce)
        encrypted[20] ^= 0xFF
        with self.assertRaises(ValueError):
            self.decrypt(bytes(encrypted), self.key)

    def test_decrypt_truncated_data_raises(self):
        """Data shorter than 12 bytes (nonce size) must raise ValueError."""
        with self.assertRaises(ValueError):
            self.decrypt(b"short", self.key)

    def test_encrypt_empty_dict(self):
        """Empty secrets dict can be encrypted and decrypted."""
        data = {}
        encrypted = self.encrypt(data, self.key)
        decrypted = self.decrypt(encrypted, self.key)
        self.assertEqual(decrypted, data)


class TestKeyDerivation(unittest.TestCase):
    """Tests HKDF-based key derivation functions."""

    def test_derive_vault_key_is_deterministic(self):
        """Same inputs always produce the same vault key."""
        from pyouro.crypto.vault import derive_vault_key
        keyring_seed = secrets.token_bytes(32)
        integrity_hash = hashlib.sha256(b"test_files").digest()
        hw_id = "MB_AABBCC|OS_11223344"

        key1 = derive_vault_key(keyring_seed, integrity_hash, hw_id)
        key2 = derive_vault_key(keyring_seed, integrity_hash, hw_id)
        self.assertEqual(key1, key2)

    def test_derive_vault_key_changes_with_hw_id(self):
        """Different HW IDs must produce different vault keys."""
        from pyouro.crypto.vault import derive_vault_key
        keyring_seed = secrets.token_bytes(32)
        integrity_hash = hashlib.sha256(b"test_files").digest()

        key1 = derive_vault_key(keyring_seed, integrity_hash, "HW_MACHINE_A")
        key2 = derive_vault_key(keyring_seed, integrity_hash, "HW_MACHINE_B")
        self.assertNotEqual(key1, key2)

    def test_derive_pysb_key_is_deterministic(self):
        """Same inputs always produce the same payload key."""
        from pyouro.crypto.vault import derive_pysb_key
        integrity_hash = hashlib.sha256(b"some_payload").digest()
        salt = secrets.token_bytes(16)
        app_name = "MyApp"

        key1 = derive_pysb_key(integrity_hash, salt, app_name)
        key2 = derive_pysb_key(integrity_hash, salt, app_name)
        self.assertEqual(key1, key2)

    def test_derive_pysb_key_changes_with_salt(self):
        """Different salts produce different payload keys."""
        from pyouro.crypto.vault import derive_pysb_key
        integrity_hash = hashlib.sha256(b"payload").digest()

        key1 = derive_pysb_key(integrity_hash, b"salt_aaa_aaaa_aa", "App")
        key2 = derive_pysb_key(integrity_hash, b"salt_bbb_bbbb_bb", "App")
        self.assertNotEqual(key1, key2)

    def test_derive_keys_are_32_bytes(self):
        """Both derived keys must be 256-bit (32 bytes) for AES-256."""
        from pyouro.crypto.vault import derive_vault_key, derive_pysb_key
        seed = secrets.token_bytes(32)
        ih = hashlib.sha256(b"x").digest()

        vault_key = derive_vault_key(seed, ih, "hw_test")
        pysb_key = derive_pysb_key(ih, secrets.token_bytes(16), "App")

        self.assertEqual(len(vault_key), 32)
        self.assertEqual(len(pysb_key), 32)


class TestIntegrityHash(unittest.TestCase):
    """Tests calculate_integrity_hash against a temporary directory."""

    def setUp(self):
        from pyouro.crypto.vault import calculate_integrity_hash
        self.calculate = calculate_integrity_hash
        # Create a temp dir with some fake Python files
        self.tmp = tempfile.mkdtemp()
        self.base = Path(self.tmp)

        (self.base / "module_a.py").write_text("print('a')", encoding="utf-8")
        (self.base / "module_b.py").write_text("print('b')", encoding="utf-8")
        self.file_order = ["module_a.py", "module_b.py"]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_hash_is_deterministic_for_same_order(self):
        """Same file_order always produces the same integrity hash."""
        h1 = self.calculate(self.file_order, self.base)
        h2 = self.calculate(self.file_order, self.base)
        self.assertEqual(h1, h2)

    def test_hash_changes_with_different_order(self):
        """Swapping the file order changes the integrity hash."""
        h1 = self.calculate(["module_a.py", "module_b.py"], self.base)
        h2 = self.calculate(["module_b.py", "module_a.py"], self.base)
        self.assertNotEqual(h1, h2)

    def test_hash_changes_when_file_is_tampered(self):
        """Modifying a file content changes the integrity hash."""
        h1 = self.calculate(self.file_order, self.base)
        (self.base / "module_a.py").write_text("print('tampered')", encoding="utf-8")
        h2 = self.calculate(self.file_order, self.base)
        self.assertNotEqual(h1, h2)

    def test_missing_file_raises_file_not_found(self):
        """A missing file in file_order raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            self.calculate(["nonexistent.py"], self.base)

    def test_empty_file_order_returns_empty_bytes(self):
        """Empty file list returns b'' without crashing."""
        result = self.calculate([], self.base)
        self.assertEqual(result, b"")

    def test_hash_is_32_bytes(self):
        """The returned hash must be 32 bytes (SHA-256 output)."""
        h = self.calculate(self.file_order, self.base)
        self.assertEqual(len(h), 32)


if __name__ == "__main__":
    unittest.main()
