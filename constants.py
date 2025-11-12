from utils import mac_to_bytes, ip_to_bytes

BROADCAST_MAC = mac_to_bytes("FF:FF:FF:FF:FF:FF")

# ethernet
IP_TYPE = 0x0800
ARP_TYPE = 0x0806

# ip
ICMP_PROT = 1
UDP_PROT = 17

# icmp
ECHO_REPLY_TYPE = 0x0
ECHO_REQUEST_TYPE = 0x8


MY_MAC = mac_to_bytes("0c:54:15:90:74:6e")
MY_IP = ip_to_bytes("10.100.102.33")
