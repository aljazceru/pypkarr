from .crypto import Crypto
from .errors import PublicKeyError

class PublicKey:
    def __init__(self, key):
        if isinstance(key, str):
            try:
                self.key = Crypto.z_base_32_decode(key)
            except ValueError:
                raise PublicKeyError("Invalid z-base-32 encoded public key")
        elif isinstance(key, bytes):
            if len(key) != 32:
                raise PublicKeyError("Public key must be 32 bytes long")
            self.key = key
        else:
            raise PublicKeyError("Public key must be bytes or z-base-32 encoded string")

    def __str__(self):
        return self.to_z32()

    def __repr__(self):
        return f"PublicKey({self.to_z32()})"

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return self.key == other.key
        return False

    def __hash__(self):
        return hash(self.key)

    def to_z32(self):
        return Crypto.z_base_32_encode(self.key)

    def to_bytes(self):
        return self.key

    def verify(self, message: bytes, signature: bytes) -> bool:
        return Crypto.verify(self.key, message, signature)