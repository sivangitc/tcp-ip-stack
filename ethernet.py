from protocol import Protocol, Raw
from layer3 import ARP, IP
from typing import Optional
from utils import *
from constants import *
from struct import unpack, pack


class Ethernet(Protocol):
    def __init__(self, *, raw: bytes = b'', src: bytes = MY_MAC, dst: bytes = BROADCAST_MAC, type: int = IP_TYPE) -> None:
        super().__init__(raw=raw)
        self.dst = dst
        self.src = src
        self.type = type
        if raw:
            self.parse()

    def parse(self) -> None:
        self.dst, self.src, self.type = unpack("!6s6sH", self.raw[:14])
        self.raw = self.raw[14:]
        self.payload = Raw(self.raw)

    def parse_next_type(self) -> None:
        raw_payload = self.raw
        if self.type == IP_TYPE:
            self.payload = IP(raw=raw_payload)
            return
        if self.type == ARP_TYPE:
            self.payload = ARP(raw=raw_payload)
            return
        self.payload = Raw(raw=raw_payload)

    def has_addr(self, addr: bytes) -> bool:
        return addr in (self.src, self.dst) or self.dst == BROADCAST_MAC

    def __repr__(self) -> str:
        src = bytes_to_mac(self.src)
        dst = bytes_to_mac(self.dst)
        return f"<{src}->{dst} {hex(self.type)} | {self.payload}>"

    def to_raw(self) -> bytes:
        raw = pack("!6s6sH", self.dst, self.src, self.type)
        raw += self.payload.to_raw()
        return raw
