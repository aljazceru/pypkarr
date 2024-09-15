import time
from dataclasses import dataclass
from typing import List, Optional
import ed25519
from dns import message, name, rdata, rdatatype, rdataclass

@dataclass
class PublicKey:
    key: bytes

    def to_z32(self) -> str:
        # Implement z-base-32 encoding here
        pass

@dataclass
class ResourceRecord:
    name: str
    rclass: int
    ttl: int
    rdata: bytes

@dataclass
class Packet:
    answers: List[ResourceRecord]

    @classmethod
    def new_reply(cls, id: int):
        return cls(answers=[])

    def build_bytes_vec_compressed(self) -> bytes:
        # Implement DNS packet compression here
        pass

@dataclass
class SignedPacket:
    public_key: PublicKey
    signature: bytes
    timestamp: int
    packet: Packet
    last_seen: int

    @classmethod
    def from_packet(cls, keypair, packet: Packet):
        timestamp = int(time.time() * 1_000_000)
        encoded_packet = packet.build_bytes_vec_compressed()

        if len(encoded_packet) > 1000:
            raise ValueError("Packet too large")

        signature = keypair.sign(cls.signable(timestamp, encoded_packet))

        return cls(
            public_key=keypair.public_key(),
            signature=signature,
            timestamp=timestamp,
            packet=packet,
            last_seen=int(time.time() * 1_000_000)
        )

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < 104:
            raise ValueError("Invalid SignedPacket bytes length")
        if len(data) > 1104:
            raise ValueError("Packet too large")

        public_key = PublicKey(data[:32])
        signature = data[32:96]
        timestamp = int.from_bytes(data[96:104], 'big')
        encoded_packet = data[104:]

        # Verify signature
        if not public_key.verify(cls.signable(timestamp, encoded_packet), signature):
            raise ValueError("Invalid signature")

        packet = Packet([])  # Parse encoded_packet into a Packet object here

        return cls(
            public_key=public_key,
            signature=signature,
            timestamp=timestamp,
            packet=packet,
            last_seen=int(time.time() * 1_000_000)
        )

    def as_bytes(self) -> bytes:
        return (
            self.public_key.key +
            self.signature +
            self.timestamp.to_bytes(8, 'big') +
            self.packet.build_bytes_vec_compressed()
        )

    def to_relay_payload(self) -> bytes:
        return self.as_bytes()[32:]

    def resource_records(self, name: str):
        origin = self.public_key.to_z32()
        normalized_name = self.normalize_name(origin, name)
        return [rr for rr in self.packet.answers if rr.name == normalized_name]

    def fresh_resource_records(self, name: str):
        origin = self.public_key.to_z32()
        normalized_name = self.normalize_name(origin, name)
        current_time = int(time.time())
        return [
            rr for rr in self.packet.answers
            if rr.name == normalized_name and rr.ttl > (current_time - self.last_seen // 1_000_000)
        ]

    def expires_in(self, min_ttl: int, max_ttl: int) -> int:
        ttl = self.ttl(min_ttl, max_ttl)
        elapsed = self.elapsed()
        return max(0, ttl - elapsed)

    def ttl(self, min_ttl: int, max_ttl: int) -> int:
        if not self.packet.answers:
            return min_ttl
        min_record_ttl = min(rr.ttl for rr in self.packet.answers)
        return max(min_ttl, min(max_ttl, min_record_ttl))

    def elapsed(self) -> int:
        return (int(time.time() * 1_000_000) - self.last_seen) // 1_000_000

    @staticmethod
    def signable(timestamp: int, v: bytes) -> bytes:
        return f"3:seqi{timestamp}e1:v{len(v)}:".encode() + v

    @staticmethod
    def normalize_name(origin: str, name: str) -> str:
        if name.endswith('.'):
            name = name[:-1]

        parts = name.split('.')
        last = parts[-1]

        if last == origin:
            return name
        if last in ('@', ''):
            return origin
        return f"{name}.{origin}"

    def __str__(self):
        records = "\n".join(
            f"        {rr.name}  IN  {rr.ttl}  {rr.rdata}"
            for rr in self.packet.answers
        )
        return f"""SignedPacket ({self.public_key.key.hex()}):
    last_seen: {self.elapsed()} seconds ago
    timestamp: {self.timestamp},
    signature: {self.signature.hex()}
    records:
{records}
"""