from scapy.all import conf, IFACES
from time import sleep
from ethernet import Ethernet
from protocol import Raw
from constants import *
from layer3 import ARP, IP, ICMP
from net_cmd import ping, arp

if __name__ == "__main__":
    # IFACES.show()
    iface = "Intel(R) Dual Band Wireless-AC 3165"
    sock = conf.L2socket(iface=iface, promisc=True)

    # p = IP(dst_ip=ip_to_bytes("1.2.3.4"))
    # p = ICMP(payload=Raw(b'abc\x00'), type=ECHO_REQUEST_TYPE)
    # print(p)
    # chk = IP.calc_checksum(bytes.fromhex("4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7"))
    # print(chk)
    # exit(0)

    ping(sock, "10.100.102.9")
    exit(0)

    while True:
        sleep(0.2)
        recv = sock.recv_raw()
        if not recv[1]:
            continue
        p = Ethernet(raw=recv[1])

        if p.type not in [ARP_TYPE, IP_TYPE]:
            print("not arp/ip", p.type, ARP_TYPE)
            continue
        
        if p.type == IP_TYPE and not isinstance(p.payload, ICMP):
            print("not icmp")
            continue

        raw = p.to_raw()

        if not raw == recv[1]:
            print(raw)
            print()
            print(recv[1])
            break
        if not p.has_addr(MY_MAC):
            print("Not for me\n")
            continue

        print(p)
        print()
