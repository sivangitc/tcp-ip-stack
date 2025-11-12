class Protocol:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.idx = 0

    def extract_field(self, length: int) -> bytes:
        field = self.raw[self.idx: self.idx + length]
        self.idx += length
        return field

    def get_next_type(self) -> None:
        return None

    def parse(self) -> None:
        raise NotImplementedError
