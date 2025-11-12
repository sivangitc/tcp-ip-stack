from ethernet import Ethernet
from protocol import Protocol
from typing import Optional, Any

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

    def load(self, l2: Protocol, l3: Optional[Protocol] = None, l4: Optional[Protocol] = None, l5: bytes = b''):
        self.l2 = l2
        self.l3 = l3
        self.l4 = l4
        self.l5 = l5
    
    def LINK(self) -> Any:
        return self.l2
    
    def IP(self) -> Any:
        return self.l3
    

    def __repr__(self) -> str:
        return f"L2({self.l2}) | L3({self.l3}) | L4({self.l4}) | L5({self.l5})"
