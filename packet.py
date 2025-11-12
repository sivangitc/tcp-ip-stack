from ethernet import Ethernet


class Packet:
    def __init__(self, frame: bytes) -> None:
        self.frame = frame
        self.l2 = Ethernet(frame)
        self.l3 = None
        self.l4 = None
        self.l5 = None

    def parse_l3(self) -> None:
        # type = self.l2.type
        # self.l3 = ...
        print("parsing L3 smoch")

    def __repr__(self) -> str:
        return f"L2({self.l2}) | L3({self.l3}) | L4({self.l4}) | L5({self.l5})"
