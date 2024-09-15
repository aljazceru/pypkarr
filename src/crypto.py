import os
import hashlib
import ed25519

class Crypto:
    @staticmethod
    def generate_keypair():
        private_key, public_key = ed25519.create_keypair()
        return private_key.to_bytes()[:32], public_key.to_bytes()

    @staticmethod
    def derive_public_key(secret_key):
        if len(secret_key) != 32:
            raise ValueError("Secret key must be 32 bytes long")
        signing_key = ed25519.SigningKey(secret_key)
        return signing_key.get_verifying_key().to_bytes()

    @staticmethod
    def sign(secret_key, message):
        if len(secret_key) != 32:
            raise ValueError("Secret key must be 32 bytes long")
        signing_key = ed25519.SigningKey(secret_key)
        return signing_key.sign(message)

    @staticmethod
    def verify(public_key, message, signature):
        verifying_key = ed25519.VerifyingKey(public_key)
        try:
            verifying_key.verify(signature, message)
            return True
        except ed25519.BadSignatureError:
            return False

    @staticmethod
    def hash(data):
        return hashlib.sha256(data).digest()

    @staticmethod
    def random_bytes(length):
        return os.urandom(length)

    @staticmethod
    def z_base_32_encode(data):
        alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
        result = ""
        bits = 0
        value = 0
        for byte in data:
            value = (value << 8) | byte
            bits += 8
            while bits >= 5:
                bits -= 5
                result += alphabet[(value >> bits) & 31]
        if bits > 0:
            result += alphabet[(value << (5 - bits)) & 31]
        return result

    @staticmethod
    def z_base_32_decode(encoded):
        alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
        alphabet_map = {char: index for index, char in enumerate(alphabet)}
        result = bytearray()
        bits = 0
        value = 0
        for char in encoded:
            value = (value << 5) | alphabet_map[char]
            bits += 5
            if bits >= 8:
                bits -= 8
                result.append((value >> bits) & 255)
        return bytes(result)