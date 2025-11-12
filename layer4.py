from protocol import Protocol, Raw
from utils import calc_checksum
from struct import pack, unpack


class UDP(Protocol):
    def __init__(self, *, raw: bytes = b'', payload: Protocol = Raw(),
                 src_port: int = 5432, dst_port: int = 80) -> None:
        super().__init__(raw=raw)
        if raw:
            self.parse()
            return
        self.src_port = src_port
        self.dst_port = dst_port
        self.payload = payload
        self.length = 8 + len(payload.to_raw())
        self.checksum = 0
        self.checksum = calc_checksum(self.raw_headers() + self.payload.to_raw())

    def parse(self) -> None:
        (self.src_port, self.dst_port, self.length, self.checksum) = unpack("!HHHH", self.raw[:8])
        self.raw = self.raw[8:]
        self.payload = Raw(self.raw)

    def raw_headers(self) -> bytes:
        return pack("!HHHH", self.src_port, self.dst_port, self.length, self.checksum)

    def to_raw(self) -> bytes:
        return self.raw_headers() + self.payload.to_raw()

    def __repr__(self) -> str:
        return f"< UDP {self.src_port} -> {self.dst_port} | {self.payload} >"
