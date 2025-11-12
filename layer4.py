from protocol import Protocol, Raw
from utils import calc_checksum
from struct import pack, unpack


class UDP(Protocol):
    def __init__(self, *, raw: bytes = b'', payload: Protocol = Raw(),
                 src_port: int = 5432, dst_port: int = 53) -> None:
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


class TCP(Protocol):
    def __init__(self, *, raw: bytes = b'', payload: Protocol = Raw(),
                 src_port: int = 5432, dst_port: int = 80) -> None:
        super().__init__(raw=raw)
        if raw:
            self.parse()
            return
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = 0
        self.ack = 0
        self.off_flags = (20 << 10) | 0
        self.window = 10000
        self.payload = payload
        self.urg_ptr = 0
        self.checksum = 0  # checksum calc needs part of IP header

    def parse(self) -> None:
        (self.src_port, self.dst_port, self.seq, self.ack, self.off_flags,
         self.window, self.checksum, self.urg_ptr) = unpack("!HHIIHHHH", self.raw[:20])
        off = self.off_flags >> 10
        self.options = b''
        if off > 20:
            self.options = self.raw[20:off]
        self.raw = self.raw[off:]
        self.payload = Raw(self.raw)

    def raw_headers(self) -> bytes:
        return pack("!HHIIHHHH", self.src_port, self.dst_port, self.seq, self.ack, self.off_flags,
                    self.window, self.checksum, self.urg_ptr)

    def to_raw(self) -> bytes:
        return self.raw_headers() + self.options + self.payload.to_raw()

    def __repr__(self) -> str:
        return f"< TCP {self.src_port} -> {self.dst_port} ack={self.ack} seq={self.seq} | {self.payload} >"
