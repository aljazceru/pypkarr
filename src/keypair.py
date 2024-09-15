from .public_key import PublicKey
from .crypto import Crypto
from .errors import KeypairError

class Keypair:
    def __init__(self, secret_key: bytes):
        if len(secret_key) != 32:
            raise KeypairError(f"Secret key must be 32 bytes long, got {len(secret_key)} bytes")
        self.secret_key = secret_key
        self.public_key = PublicKey(Crypto.derive_public_key(secret_key))

    @classmethod
    def random(cls) -> 'Keypair':
        """Generate a new random keypair."""
        secret_key, _ = Crypto.generate_keypair()
        return cls(secret_key)

    @classmethod
    def from_secret_key(cls, secret_key: bytes) -> 'Keypair':
        """Create a Keypair from a secret key."""
        return cls(secret_key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message using this keypair."""
        return Crypto.sign(self.secret_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature using this keypair's public key."""
        return self.public_key.verify(message, signature)

    def to_bytes(self) -> bytes:
        """Return the secret key bytes."""
        return self.secret_key

    @classmethod
    def from_bytes(cls, secret_key: bytes) -> 'Keypair':
        """Create a Keypair from bytes."""
        return cls(secret_key)

    def __str__(self):
        return f"Keypair(public_key={self.public_key})"

    def __repr__(self):
        return self.__str__()