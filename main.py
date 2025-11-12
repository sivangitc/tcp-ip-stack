from scapy.all import conf, IFACES
from time import sleep
from packet import Packet

MY_MAC = "0c:54:15:90:74:6e"

if __name__ == "__main__":
    # IFACES.show()
    iface = "Intel(R) Dual Band Wireless-AC 3165"
    sock = conf.L2socket(iface=iface, promisc=True)

    while True:
        sleep(0.5)
        recv = sock.recv_raw()
        if not recv[1]:
            continue
        p = Packet(recv[1])
        print(p)
        p.l2.get_next_type()
        if not p.l2.has_addr(MY_MAC):
            print("Not for me\n")
            continue
        p.parse_l3()
        print()
