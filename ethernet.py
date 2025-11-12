from protocol import Protocol


class Ethernet(Protocol):
    MAC_LEN = 6
    BROADCAST_ADDR = "FF:FF:FF:FF:FF:FF"

    IP_TYPE = bytes.fromhex('0800')
    ARP_TYPE = bytes.fromhex('0806')

    def __init__(self, raw: bytes) -> None:
        super().__init__(raw)
        self.parse()

    def parse(self) -> None:
        self.dst = self.extract_field(self.MAC_LEN).hex(':').upper()
        self.src = self.extract_field(self.MAC_LEN).hex(':').upper()
        self.type = self.extract_field(2)

    def get_next_type(self) -> None:
        """Returns class of the next layer. for now returns None always bc i didnt implement anything"""
        if self.type == self.IP_TYPE:
            return None
        if self.type == self.ARP_TYPE:
            return None
        return None

    def has_addr(self, addr: str) -> bool:
        return addr.upper() in (self.src, self.dst) or self.dst == self.BROADCAST_ADDR

    def __repr__(self) -> str:
        return f"<{self.src}> -> <{self.dst}> : 0x{self.type.hex()}"
