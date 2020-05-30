#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dhcpv6_server.py: SLAAC/DHCPv6 server (dhcpv6_server)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Servers.dhcpv6_server import DHCPv6Server
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
__script_name__ = 'SLAAC/DHCPv6 server (dhcpv6_server)'
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
    parser.add_argument('-p', '--prefix', type=str, help='Set network prefix', default='fde4:8dba:82e1:ffff::/64')
    parser.add_argument('-f', '--first_suffix', type=int, help='Set first suffix client IPv6 for offering', default=2)
    parser.add_argument('-l', '--last_suffix', type=int, help='Set last suffix client IPv6 for offering', default=65534)
    parser.add_argument('-t', '--target_mac', type=str, help='Set target MAC address', default=None)
    parser.add_argument('-T', '--target_ipv6', type=str, help='Set client Global IPv6 address with MAC --target_mac',
                        default=None)
    parser.add_argument('-D', '--disable_dhcpv6', action='store_true', help='Do not use DHCPv6 protocol')
    parser.add_argument('-d', '--dns', type=str, help='Set recursive DNS IPv6 address', default=None)
    parser.add_argument('-s', '--dns_search', type=str, help='Set DNS search domain', default='domain.local')
    parser.add_argument('--delay', type=int, help='Set delay between packets', default=1)
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
        dhcpv6_server: DHCPv6Server = DHCPv6Server(network_interface=current_network_interface)
        dhcpv6_server.start(target_mac_address=args.target_mac,
                            target_ipv6_address=args.target_ipv6,
                            first_ipv6_address_suffix=args.first_suffix,
                            last_ipv6_address_suffix=args.last_suffix,
                            dns_server_ipv6_address=args.dns,
                            ipv6_prefix=args.prefix,
                            domain_search=args.dns_search,
                            disable_dhcpv6=args.disable_dhcpv6,
                            quiet=args.quiet)

    except KeyboardInterrupt:
        base.print_info('Exit ....')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)
# endregion


# region Call Main function
if __name__ == '__main__':
    main()
# endregion
