import base64
import unittest
from unittest.mock import patch
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from helper.crypto import encrypt_secret


class CryptoConfigurationTests(unittest.TestCase):
    def test_legacy_public_key_formats_encrypt_the_same_entity_secret(self):
        key = RSA.generate(2048)
        pem = key.public_key().export_key().decode()
        bare = "".join(pem.splitlines()[1:-1])
        formats = [pem, pem.replace("\n", "\\n"), bare,
                   " ".join(bare[i:i + 64] for i in range(0, len(bare), 64)),
                   "\\n" + bare + "\\n"]
        for raw in formats:
            with self.subTest(format_index=formats.index(raw)):
                with patch.dict("os.environ", {"ENTITY_SECRET": "1a" * 32, "PUBLIC_KEY": raw}):
                    encrypted = base64.b64decode(encrypt_secret())
                self.assertEqual(PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(encrypted), bytes.fromhex("1a" * 32))
