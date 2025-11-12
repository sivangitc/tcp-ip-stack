from protocol import Protocol, Raw
from layer3 import ARP
from typing import Optional
from utils import *
from constants import *


class Ethernet(Protocol):
    def __init__(self, *, raw: bytes = b'', src: str = '', dst: str = '', type: bytes = b'') -> None:
        super().__init__(raw)
        self.dst = dst
        self.src = src
        self.type = type
        if raw:
            self.parse()

    def parse(self) -> None:        
        self.dst = bytes_to_mac(self.extract_field(6))
        self.src = bytes_to_mac(self.extract_field(6))
        self.type = self.extract_field(2)
        self.payload = Raw(self.raw)

    def parse_next_type(self) -> None:
        raw_payload = self.raw
        if self.type == IP_TYPE:
            self.payload = Raw(raw=raw_payload)
            return
        if self.type == ARP_TYPE:
            self.payload = ARP(raw=raw_payload)
            return
        self.payload = Raw(raw=raw_payload)

    def has_addr(self, addr: str) -> bool:
        return addr.upper() in (self.src, self.dst) or self.dst == BROADCAST_MAC

    def __repr__(self) -> str:
        return f"<{self.src}->{self.dst} 0x{self.type.hex()} | {self.payload}>"


    def to_raw(self) -> bytes:
        raw = b''
        raw += mac_to_bytes(self.dst)
        raw += mac_to_bytes(self.src)
        raw += self.type
        if self.payload:
            raw += self.payload.to_raw()
        return raw
