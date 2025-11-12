from protocol import Protocol, Raw
from constants import ECHO_REPLY_TYPE, ICMP_PROT, MY_IP, UDP_PROT, BROADCAST_MAC, IP_TYPE, MY_MAC
from utils import calc_checksum, bytes_to_ip, bytes_to_mac
from struct import pack, unpack
from layer4 import UDP


class ICMP(Protocol):
    def __init__(self, *, raw: bytes = b'', type: int = ECHO_REPLY_TYPE, code: int = 0,
                 payload: Raw = Raw()) -> None:
        super().__init__(raw=raw)
        if raw:
            self.parse()
            return
        self.type = type
        self.code = code
        self.rest = bytes.fromhex("00 00 00 00")
        self.payload = payload
        self.checksum = 0
        self.checksum = calc_checksum(self.raw_headers() + self.payload.to_raw())

    def parse(self) -> None:
        (self.type, self.code, self.checksum, self.rest) = unpack("!BBH4s", self.raw[:8])
        self.raw = self.raw[8:]
        self.payload = Raw(self.raw)

    def raw_headers(self) -> bytes:
        return pack("!BBH4s", self.type, self.code, self.checksum, self.rest)

    def to_raw(self) -> bytes:
        return self.raw_headers() + self.payload.to_raw()

    def __repr__(self) -> str:
        return f"<ICMP {self.type} {self.code} | {self.payload} >"


class IP(Protocol):
    def __init__(self, *, raw: bytes = b'', prot: int = ICMP_PROT, payload: Protocol = Raw(),
                 src_ip: bytes = MY_IP, dst_ip: bytes = b'') -> None:
        super().__init__(raw=raw)
        if raw:
            self.parse()
            return
        self.ver_hlen = 0x45
        self.dsf = 0x00
        self.total_length = len(payload.to_raw()) + 20
        self.identification = 3
        self.fl_fo = 0x0000
        self.ttl = 64
        self.prot = prot
        self.hdr_checksum = 0
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.optional = b''
        self.payload = payload
        self.hdr_checksum = calc_checksum(self.raw_headers())

    def parse(self) -> None:
        (self.ver_hlen, self.dsf, self.total_length, self.identification, self.fl_fo, self.ttl,
         self.prot, self.hdr_checksum, self.src_ip, self.dst_ip) = unpack("!BBHHHBBH4s4s", self.raw[:20])
        self.hdr_len = (self.ver_hlen & 0xF) * 4
        self.optional = b''
        if self.hdr_len > 20:
            self.optional = self.raw[20: self.hdr_len]
        self.raw = self.raw[self.hdr_len:]
        self.payload = Raw(self.raw)
        self.parse_next_type()

    def parse_next_type(self) -> None:
        if self.prot == ICMP_PROT:
            self.payload = ICMP(raw=self.raw)
        if self.prot == UDP_PROT:
            self.payload = UDP(raw=self.raw)

    def raw_headers(self) -> bytes:
        return pack("!BBHHHBBH4s4s", self.ver_hlen, self.dsf, self.total_length,
                    self.identification, self.fl_fo, self.ttl, self.prot, self.hdr_checksum,
                    self.src_ip, self.dst_ip)

    def to_raw(self) -> bytes:
        return self.raw_headers() + self.optional + self.payload.to_raw()

    def __repr__(self) -> str:
        src = bytes_to_ip(self.src_ip)
        dst = bytes_to_ip(self.dst_ip)
        return f"< IP {src} -> {dst} ttl={self.ttl} prot={self.prot} | {self.payload} >"


class ARP(Protocol):
    REQUEST_TYPE = 0x0001
    REPLY_TYPE = 0x0002

    def __init__(self, *, raw: bytes = b'', opcode: int = REQUEST_TYPE, src_mac: bytes = MY_MAC,
                 dst_mac: bytes = BROADCAST_MAC, src_ip: bytes = MY_IP, dst_ip: bytes = b'') -> None:
        super().__init__(raw=raw)
        if raw:
            self.parse()
            return
        self.hw_type = 0x0001
        self.prot = IP_TYPE
        self.hw_size = 0x06
        self.prot_size = 0x04
        self.opcode = opcode
        self.sender_mac = src_mac
        self.sender_ip = src_ip
        self.target_mac = dst_mac
        self.target_ip = dst_ip
        self.payload = Raw()

    def parse(self) -> None:
        (self.hw_type, self.prot, self.hw_size, self.prot_size, self.opcode, self.sender_mac,
         self.sender_ip, self.target_mac, self.target_ip) = unpack("!HHBBH6s4s6s4s", self.raw[:28])
        self.payload = Raw(self.raw[28:])

    def to_raw(self) -> bytes:
        return pack("!HHBBH6s4s6s4s", self.hw_type, self.prot, self.hw_size, self.prot_size, self.opcode,
                    self.sender_mac, self.sender_ip, self.target_mac, self.target_ip) + self.payload.to_raw()

    def __repr__(self) -> str:
        if self.opcode == self.REQUEST_TYPE:
            return f"< {bytes_to_ip(self.target_ip)}? tell {bytes_to_ip(self.sender_ip)} >"
        if self.opcode == self.REPLY_TYPE:
            return f"< {bytes_to_ip(self.sender_ip)} at {bytes_to_mac(self.sender_mac)} >"
        return f"< ARP {bytes_to_ip(self.sender_ip)}->{bytes_to_ip(self.target_ip)} {self.opcode} >"
