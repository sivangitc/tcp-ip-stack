
def bytes_to_mac(addr: bytes) -> str:
    return addr.hex(':').upper()

def mac_to_bytes(addr: str) -> bytes:
    addr = ''.join(addr.split(':'))
    addr = ''.join(addr.split('-'))
    return bytes.fromhex(addr)

def ip_to_bytes(addr: str) -> bytes:
    return bytes([int(x) for x in addr.split('.')])

def bytes_to_ip(addr: bytes) -> str:
    return '.'.join([str(int(x)) for x in addr])