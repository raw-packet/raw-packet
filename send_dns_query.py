from base import Base
from network import Ethernet_raw, DNS_raw
from argparse import ArgumentParser
from sys import exit

if __name__ == "__main__":

    Base.check_user()
    Base.check_platform()

    NAMES = []

    parser = ArgumentParser(description='DNS Query sender')

    parser.add_argument('-i', '--interface', type=str, help='Set interface name for send DNS query packets')
    parser.add_argument('-M', '--notspoofmac', help='Don\'t spoof MAC address', action='store_true')
    parser.add_argument('-I', '--notspoofip', help='Don\'t spoof IP address', action='store_true')

    parser.add_argument('-p', '--packets', type=int,
                        help='Number of packets in one iteration (default: 500000)', default=500000)
    parser.add_argument('-k', '--iterations', type=int,
                        help='Number of iterations (default: 100000)', default=100000)

    parser.add_argument('-d', '--domain', type=str, required=True, help='Target domain name (example: test.com)')
    parser.add_argument('-s', '--nsservers', type=str, help='NS servers (example: "ns1,ns2")')
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

    current_network_interface = Base.netiface_selection()

