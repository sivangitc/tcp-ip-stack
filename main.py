from scapy.all import conf, IFACES
from time import sleep
from ethernet import Ethernet
from protocol import Raw
from constants import *
from layer3 import ARP

if __name__ == "__main__":
    # IFACES.show()
    iface = "Intel(R) Dual Band Wireless-AC 3165"
    sock = conf.L2socket(iface=iface, promisc=True)

    while True:
        sleep(0.5)
        recv = sock.recv_raw()
        if not recv[1]:
            continue
        p = Ethernet(raw=recv[1])
        p.parse_next_type()

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
