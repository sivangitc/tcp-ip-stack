from typing import Optional


class Protocol:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.payload: Optional["Protocol"] = None

    def extract_field(self, length: int) -> bytes:
        field = self.raw[:length]
        self.raw = self.raw[length:]
        return field

    def parse_next_type(self) -> Optional["Protocol"]:
        return None

    def parse(self) -> None:
        raise NotImplementedError
    
    def to_raw(self) -> bytes:
        raise NotImplementedError

    def __repr__(self) -> str:
        raise NotImplementedError


class Raw(Protocol):
    def parse(self) -> None:
        print("Not Parsing Raw")

    def to_raw(self) -> bytes:
        return self.raw
    
    def __repr__(self) -> str:
        return f"< Raw {len(self.raw)}B >"
