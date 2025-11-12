from protocol import Protocol
from constants import *
from utils import *


class ARP(Protocol):
    REQUEST_TYPE = bytes.fromhex('0001')
    REPLY_TYPE = bytes.fromhex('0002')

    def __init__(self, *, raw: bytes = b'', opcode: bytes = REQUEST_TYPE, src_mac: str = MY_MAC, 
                 dst_mac: str = BROADCAST_MAC, src_ip: str = MY_IP, dst_ip: str = '') -> None:
        super().__init__(raw)
        if raw:
            self.parse()
            return
        self.hw_type = b'\x00\x01'
        self.prot = IP_TYPE
        self.hw_size = b'\x06'
        self.prot_size = b'\x04'
        self.opcode = opcode
        self.sender_mac = src_mac
        self.sender_ip = src_ip
        self.target_mac = dst_mac
        self.target_ip = dst_ip

    def parse(self) -> None:
        self.hw_type = self.extract_field(2)
        self.prot = self.extract_field(2)
        self.hw_size = self.extract_field(1)
        self.prot_size = self.extract_field(1)
        self.opcode = self.extract_field(2)
        self.sender_mac = bytes_to_mac(self.extract_field(6))
        self.sender_ip = bytes_to_ip(self.extract_field(4))
        self.target_mac = bytes_to_mac(self.extract_field(6))
        self.target_ip = bytes_to_ip(self.extract_field(4))

    def to_raw(self) -> bytes:
        raw = b''
        raw += self.hw_type
        raw += self.prot
        raw += self.hw_size
        raw += self.prot_size
        raw += self.opcode
        raw += mac_to_bytes(self.sender_mac)
        raw += ip_to_bytes(self.sender_ip)
        raw += mac_to_bytes(self.target_mac)
        raw += ip_to_bytes(self.target_ip)
        return raw

    def __repr__(self) -> str:
        if self.opcode == self.REQUEST_TYPE:
            return f"< {self.target_ip}? tell {self.sender_ip} >"
        if self.opcode == self.REPLY_TYPE:
            return f"< {self.sender_ip} at {self.sender_mac} >"
        return f"< {self.sender_ip}->{self.target_ip} {self.opcode} >"
