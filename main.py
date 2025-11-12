from scapy.all import conf
from time import sleep
from ethernet import Ethernet
from constants import MY_MAC

if __name__ == "__main__":
    iface = "Intel(R) Dual Band Wireless-AC 3165"
    sock = conf.L2socket(iface=iface, promisc=True)

    while True:
        sleep(0.2)
        recv = sock.recv_raw()
        if not recv[1]:
            continue
        p = Ethernet(raw=recv[1])

        if not p.has_addr(MY_MAC):
            print("Not for me\n")
            continue

        print(p)
        print()
