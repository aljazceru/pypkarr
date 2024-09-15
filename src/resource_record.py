from dataclasses import dataclass
from typing import Union
import ipaddress

@dataclass
class ResourceRecord:
    name: str
    rclass: str
    ttl: int
    rtype: str
    rdata: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]

    def __post_init__(self):
        self.name = self.name.lower()
        self.rclass = self.rclass.upper()
        self.rtype = self.rtype.upper()

        if self.rtype == 'A':
            self.rdata = ipaddress.IPv4Address(self.rdata)
        elif self.rtype == 'AAAA':
            self.rdata = ipaddress.IPv6Address(self.rdata)

    def to_wire_format(self) -> bytes:
        # This is a placeholder. You'll need to implement the actual DNS wire format encoding.
        pass

    @classmethod
    def from_wire_format(cls, wire_data: bytes) -> 'ResourceRecord':
        # This is a placeholder. You'll need to implement the actual DNS wire format decoding.
        pass

    def __str__(self):
        return f"{self.name} {self.ttl} {self.rclass} {self.rtype} {self.rdata}"

    def is_expired(self, current_time: int) -> bool:
        return current_time > self.ttl

    def remaining_ttl(self, current_time: int) -> int:
        return max(0, self.ttl - current_time)