from struct import unpack_from


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


def calc_checksum(data: bytes) -> int:
    """return InternetChecksum(data)"""
    if len(data) % 2 != 0:
        data += b'\x00'
    sum = 0
    for i in range(len(data) // 2):
        sum += unpack_from("!H", buffer=data, offset=i * 2)[0]
    sum += sum >> 16
    sum = ((~sum) & 0xFFFF)
    return sum
