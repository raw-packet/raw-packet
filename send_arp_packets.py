from base import Base
from network import Ethernet
from argparse import ArgumentParser
from scapy.all import Ether, IP, ARP, sendp

Base.check_user()

parser = ArgumentParser(description='ARP reply sender')

parser.add_argument('-i', '--interface', type=str, help='Set interface name for send reply packets')
parser.add_argument('-c', '--count', type=int, help='Set count of nak requests (default: 3)', default=3)
parser.add_argument('-t', '--target_mac', type=str, required=True, help='Set target client mac address')
parser.add_argument('-o', '--target_ip', type=str, required=True, help='Set target client ip address')
parser.add_argument('-d', '--sender_mac', type=str, help='Set sender mac address, if not set use random mac')
parser.add_argument('-p', '--sender_ip', type=str, required=True, help='Set sender IP address')

args = parser.parse_args()

current_network_interface = None
sender_mac_address = None
sender_ip_address = None

eth = Ethernet()

if args.interface is None:
    current_network_interface = Base.netiface_selection()
else:
    current_network_interface = args.interface

if args.sender_mac is None:
    sender_mac_address = eth.get_random_mac()
else:
    sender_mac_address = args.sender_mac

print "\r\nNetwork interface: " + current_network_interface
print "Target mac address: " + args.target_mac
print "Target IP address: " + args.target_ip
print "Sender mac address: " + sender_mac_address
print "Sender ip address: " + args.sender_ip + "\r\n"


def make_arp_reply_packet():
    return (Ether(src=sender_mac_address, dst=args.target_mac) /
            ARP(hwsrc=sender_mac_address, psrc=args.sender_ip,
                hwdst=args.target_mac, pdst=args.target_ip))


if __name__ == "__main__":
    print "Sending ARP responses ..."
    arp_reply_packet = make_arp_reply_packet()
    for _ in range(args.count):
        sendp(arp_reply_packet, iface=current_network_interface, verbose=False)
