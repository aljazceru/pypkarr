from dataclasses import dataclass, field
from typing import List, Optional
from dns import message, name, rdata, rdatatype, rdataclass
from .resource_record import ResourceRecord
from .errors import PacketError

@dataclass
class Packet:
    answers: List[ResourceRecord] = field(default_factory=list)
    id: int = 0
    qr: bool = True  # True for response, False for query
    opcode: int = 0  # 0 for standard query
    aa: bool = True  # Authoritative Answer
    tc: bool = False  # TrunCation
    rd: bool = False  # Recursion Desired
    ra: bool = False  # Recursion Available
    z: int = 0  # Reserved for future use
    rcode: int = 0  # Response code

    @classmethod
    def new_reply(cls, id: int):
        return cls(answers=[], id=id)

    def add_answer(self, answer: ResourceRecord):
        self.answers.append(answer)

    def build_bytes_vec_compressed(self) -> bytes:
        """Build a compressed DNS wire format representation of the packet."""
        try:
            msg = message.Message(id=self.id)
            msg.flags = 0
            if self.qr:
                msg.flags |= 1 << 15
            msg.flags |= (self.opcode & 0xF) << 11
            if self.aa:
                msg.flags |= 1 << 10
            if self.tc:
                msg.flags |= 1 << 9
            if self.rd:
                msg.flags |= 1 << 8
            if self.ra:
                msg.flags |= 1 << 7
            msg.flags |= (self.z & 0x7) << 4
            msg.flags |= self.rcode & 0xF

            for rr in self.answers:
                rr_name = name.from_text(rr.name)
                rr_ttl = rr.ttl
                rr_rdataclass = rdataclass.from_text(rr.rclass)
                rr_rdatatype = rdatatype.from_text(rr.rtype)
                rr_rdata = rdata.from_text(rr_rdataclass, rr_rdatatype, rr.rdata)
                msg.answer.append((rr_name, rr_ttl, rr_rdata))

            return msg.to_wire()
        except Exception as e:
            raise PacketError(f"Failed to build packet: {str(e)}")

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Packet':
        """Create a Packet object from DNS wire format bytes."""
        try:
            msg = message.from_wire(data)
            packet = cls(
                id=msg.id,
                qr=bool(msg.flags & (1 << 15)),
                opcode=(msg.flags >> 11) & 0xF,
                aa=bool(msg.flags & (1 << 10)),
                tc=bool(msg.flags & (1 << 9)),
                rd=bool(msg.flags & (1 << 8)),
                ra=bool(msg.flags & (1 << 7)),
                z=(msg.flags >> 4) & 0x7,
                rcode=msg.flags & 0xF
            )

            for rrset in msg.answer:
                for rr in rrset:
                    resource_record = ResourceRecord(
                        name=rrset.name.to_text(),
                        rclass=rdataclass.to_text(rr.rdclass),
                        ttl=rrset.ttl,
                        rtype=rdatatype.to_text(rr.rdtype),
                        rdata=rr.to_text()
                    )
                    packet.add_answer(resource_record)

            return packet
        except Exception as e:
            raise PacketError(f"Failed to parse packet: {str(e)}")

    def __str__(self):
        header = f"Packet ID: {self.id}, QR: {'Response' if self.qr else 'Query'}, " \
                 f"Opcode: {self.opcode}, AA: {self.aa}, TC: {self.tc}, RD: {self.rd}, " \
                 f"RA: {self.ra}, Z: {self.z}, RCODE: {self.rcode}"
        answers = "\n".join(f"  {rr}" for rr in self.answers)
        return f"{header}\nAnswers:\n{answers}"