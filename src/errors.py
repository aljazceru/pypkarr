class PkarrError(Exception):
    """Base class for all pkarr-related errors."""
    pass

class KeypairError(PkarrError):
    """Raised when there's an issue with keypair operations."""
    pass

class PublicKeyError(PkarrError):
    """Raised when there's an issue with public key operations."""
    pass

class SignatureError(PkarrError):
    """Raised when there's an issue with signature operations."""
    pass

class PacketError(PkarrError):
    """Raised when there's an issue with packet operations."""
    pass

class DNSError(PkarrError):
    """Raised when there's an issue with DNS operations."""
    pass

class DHTError(PkarrError):
    """Raised when there's an issue with DHT operations."""
    pass

class InvalidSignedPacketBytesLength(PacketError):
    """Raised when the SignedPacket bytes length is invalid."""
    def __init__(self, length: int):
        super().__init__(f"Invalid SignedPacket bytes length, expected at least 104 bytes but got: {length}")

class InvalidRelayPayloadSize(PacketError):
    """Raised when the relay payload size is invalid."""
    def __init__(self, size: int):
        super().__init__(f"Invalid relay payload size, expected at least 72 bytes but got: {size}")

class PacketTooLarge(PacketError):
    """Raised when the DNS packet is too large."""
    def __init__(self, size: int):
        super().__init__(f"DNS Packet is too large, expected max 1000 bytes but got: {size}")

class DHTIsShutdown(DHTError):
    """Raised when the DHT is shutdown."""
    def __init__(self):
        super().__init__("DHT is shutdown")

class PublishInflight(DHTError):
    """Raised when a publish query is already in flight for the same public key."""
    def __init__(self):
        super().__init__("Publish query is already in flight for the same public_key")