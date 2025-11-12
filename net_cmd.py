from scapy.all import conf, IFACES
from constants import *
from utils import *
from struct import pack, unpack, unpack_from
from layer3 import ICMP, IP, ARP
from ethernet import Ethernet
from protocol import Raw
from time import sleep, time_ns

def ping(sock, dst_ip_s: str) -> None:
    dst_ip = ip_to_bytes(dst_ip_s)
    icmp = ICMP(type=ECHO_REQUEST_TYPE, payload=Raw(b"CYBERS"))
    ip = IP(prot=ICMP_PROT, payload=icmp, dst_ip=dst_ip)
    dst_mac = mac_to_bytes(arp(sock, dst_ip_s))
    eth = Ethernet(payload=ip, dst=dst_mac)

    start = time_ns()
    sock.send(eth.to_raw())
    while True:
        sleep(0.1)
        recv = sock.recv_raw()
        if not recv[1]:
            continue    
        p = Ethernet(raw=recv[1])
        if not isinstance(p.payload, IP) or not isinstance(p.payload.payload, ICMP):
            continue
        if p.payload.src_ip == dst_ip:
            took = (time_ns() - start) // 1_000_000
            print(f"ICMP reply from {dst_ip_s}: time={took}ms ttl={p.payload.ttl}")
            return


def arp(sock, dst_ip_s: str) -> str:
    dst_ip = ip_to_bytes(dst_ip_s)
    arp = ARP(dst_ip=dst_ip)
    eth = Ethernet(type=ARP_TYPE, payload=arp)

    sock.send(eth.to_raw())
    while True:
        sleep(0.1)
        recv = sock.recv_raw()
        if not recv[1]:
            continue    
        p = Ethernet(raw=recv[1])
        if not isinstance(p.payload, ARP):
            continue
        if p.payload.sender_ip == dst_ip:
            print(f"ARP {dst_ip_s} reply: {p.payload}")
            return bytes_to_mac(p.payload.sender_mac)
