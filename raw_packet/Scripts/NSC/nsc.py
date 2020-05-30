#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
nsc.py: Network Security Check (nsc)
        Checking network security mechanisms such as: Dynamic ARP Inspection, DHCP snooping, etc.
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.nsc import NetworkSecurityCheck
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from typing import List, Dict, Union
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
__script_name__ = 'Network Security Check (nsc)'
# endregion


# region Main function
def main() -> None:
    """
    Start Network Security Check (nsc)
    :return: None
    """

    # region Init Raw-packet classes
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    nsc: NetworkSecurityCheck = NetworkSecurityCheck()
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--send_interface', help='Set interface name for send packets', default=None)
    parser.add_argument('-l', '--listen_interface', help='Set interface name for listen packets', default=None)
    parser.add_argument('-n', '--test_host_interface', help='Set test host network interface for listen packets',
                        default=None)
    parser.add_argument('-t', '--test_host_ip', help='Set test host IP address for ssh connection', default=None)
    parser.add_argument('-m', '--test_host_mac', help='Set test host MAC address for ssh connection', default=None)
    parser.add_argument('-o', '--test_host_os', help='Set test host OS (MacOS, Linux, Windows)', default='Linux')
    parser.add_argument('-u', '--test_ssh_user', help='Set test host user name for ssh connection', default='root')
    parser.add_argument('-p', '--test_ssh_pass', help='Set test host password for ssh connection', default=None)
    parser.add_argument('-k', '--test_ssh_pkey', help='Set test host private key for ssh connection', default=None)
    parser.add_argument('-G', '--gateway_ip', help='Set gateway IPv4 address', default=None)
    parser.add_argument('-g', '--gateway_mac', help='Set gateway MAC address', default=None)
    parser.add_argument('-r', '--number_of_packets', type=int, default=10,
                        help='Set number of spoofing packets for each test (default: 10)')
    parser.add_argument('-L', '--listen_time', type=int, default=60,
                        help='Set time to listen spoofing packets in seconds (default: 60)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner
    if not args.quiet:
        base.print_banner(__script_name__)
    # endregion

    # region Set current network interface
    send_network_interface: str = \
        base.network_interface_selection(interface_name=args.send_interface,
                                         message='Please select a network interface for ' +
                                                 'send spoofing packets from table: ')
    # endregion

    try:
        # region Start Network Security Check
        network_security_mechanisms: Dict[str, Union[bool, List[str]]] = \
            nsc.check(send_interface=send_network_interface,
                      listen_interface=args.listen_interface,
                      gateway_ipv4_address=args.gateway_ip,
                      gateway_mac_address=args.gateway_mac,
                      test_host_os=args.test_host_os,
                      test_host_interface=args.test_host_interface,
                      test_host_ipv4_address=args.test_host_ip,
                      test_host_mac_address=args.test_host_mac,
                      test_host_ssh_user=args.test_ssh_user,
                      test_host_ssh_pass=args.test_ssh_pass,
                      test_host_ssh_pkey=args.test_ssh_pkey,
                      number_of_packets=args.number_of_packets,
                      listen_time=args.listen_time,
                      quiet=args.quiet)
        # endregion

        # region Print results
        base.print_info(__script_name__ + ' results:')
        for key in network_security_mechanisms.keys():
            if isinstance(network_security_mechanisms[key], bool):
                if not network_security_mechanisms[key]:
                    base.print_success(key + ' ', 'disabled')
                else:
                    base.print_error(key + ' ', 'enabled')
            if isinstance(network_security_mechanisms[key], List):
                if len(network_security_mechanisms[key]) > 0:
                    base.print_success('Sniff ' + key + ' from: ', str(network_security_mechanisms[key]))
                else:
                    base.print_error(key + ' ', 'not found')
        # endregion

    except KeyboardInterrupt:
        if not args.quiet:
            base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        if not args.quiet:
            base.print_error(Error.args[0])
        exit(1)

# endregion


# region Call Main function
if __name__ == "__main__":
    main()
# endregion
