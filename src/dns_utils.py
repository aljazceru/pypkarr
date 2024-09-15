import struct
from typing import List, Tuple
from dns import message, name, rdata, rdatatype, rdataclass
from .errors import DNSError

def create_dns_query(domain: str, record_type: str) -> bytes:
    """Create a DNS query packet."""
    try:
        qname = name.from_text(domain)
        q = message.make_query(qname, rdatatype.from_text(record_type))
        return q.to_wire()
    except Exception as e:
        raise DNSError(f"Failed to create DNS query: {str(e)}")

def parse_dns_response(response: bytes) -> List[Tuple[str, str, int, str]]:
    """Parse a DNS response and return a list of (name, type, ttl, data) tuples."""
    try:
        msg = message.from_wire(response)
        results = []
        for rrset in msg.answer:
            name = rrset.name.to_text()
            ttl = rrset.ttl
            for rr in rrset:
                rr_type = rdatatype.to_text(rr.rdtype)
                rr_data = rr.to_text()
                results.append((name, rr_type, ttl, rr_data))
        return results
    except Exception as e:
        raise DNSError(f"Failed to parse DNS response: {str(e)}")

def compress_domain_name(domain: str) -> bytes:
    """Compress a domain name according to DNS name compression rules."""
    try:
        n = name.from_text(domain)
        return n.to_wire()
    except Exception as e:
        raise DNSError(f"Failed to compress domain name: {str(e)}")

def decompress_domain_name(compressed: bytes, offset: int = 0) -> Tuple[str, int]:
    """Decompress a domain name from DNS wire format."""
    try:
        n, offset = name.from_wire(compressed, offset)
        return n.to_text(), offset
    except Exception as e:
        raise DNSError(f"Failed to decompress domain name: {str(e)}")

def encode_resource_record(name: str, rr_type: str, rr_class: str, ttl: int, rdata: str) -> bytes:
    """Encode a resource record into DNS wire format."""
    try:
        n = name.from_text(name)
        rr_type = rdatatype.from_text(rr_type)
        rr_class = rdataclass.from_text(rr_class)
        rd = rdata.from_text(rr_type, rr_class, rdata)
        return (n.to_wire() + 
                struct.pack("!HHIH", rr_type, rr_class, ttl, len(rd.to_wire())) + 
                rd.to_wire())
    except Exception as e:
        raise DNSError(f"Failed to encode resource record: {str(e)}")

def decode_resource_record(wire: bytes, offset: int = 0) -> Tuple[str, str, str, int, str, int]:
    """Decode a resource record from DNS wire format."""
    try:
        n, offset = name.from_wire(wire, offset)
        rr_type, rr_class, ttl, rdlen = struct.unpack_from("!HHIH", wire, offset)
        offset += 10
        rd = rdata.from_wire(rdatatype.to_text(rr_type), wire, offset, rdlen)
        offset += rdlen
        return (n.to_text(), 
                rdatatype.to_text(rr_type), 
                rdataclass.to_text(rr_class), 
                ttl, 
                rd.to_text(), 
                offset)
    except Exception as e:
        raise DNSError(f"Failed to decode resource record: {str(e)}")

def is_valid_domain_name(domain: str) -> bool:
    """Check if a given string is a valid domain name."""
    try:
        name.from_text(domain)
        return True
    except Exception:
        return False

def normalize_domain_name(domain: str) -> str:
    """Normalize a domain name (convert to lowercase and ensure it ends with a dot)."""
    try:
        n = name.from_text(domain)
        return n.to_text().lower()
    except Exception as e:
        raise DNSError(f"Failed to normalize domain name: {str(e)}")