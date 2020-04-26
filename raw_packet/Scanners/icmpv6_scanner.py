# region Description
"""
scanner.py: Scan local network
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import RawEthernet, RawIPv6, RawICMPv6, RawSniff, RawSend
from raw_packet.Utils.tm import ThreadManager
# endregion

# region Import libraries
from time import sleep
from random import randint
from typing import Union, Dict, List
# endregion

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
# endregion


# region class ICMPv6 scanner
class ICMPv6Scan:

    # region Set variables
    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    ipv6: RawIPv6 = RawIPv6()
    icmpv6: RawICMPv6 = RawICMPv6()
    raw_sniff: RawSniff = RawSniff()
    thread_manager: ThreadManager = ThreadManager(2)

    network_interface: Union[None, str] = None
    your_mac_address: Union[None, str] = None
    your_ipv6_link_address: Union[None, str] = None
    target_mac_address: str = '33:33:00:00:00:01'

    results: List[Dict[str, str]] = list()
    unique_results: List[Dict[str, str]] = list()
    mac_addresses: List[str] = list()

    retry_number: int = 3
    timeout: int = 3

    icmpv6_identifier: int = 0

    router_info: Dict[str, Union[int, str]] = dict()
    router_search: bool = False
    # endregion

    # region Init
    def __init__(self, network_interface: str) -> None:
        """
        Init
        :param network_interface: Network interface name (example: 'eth0')
        """
        self.network_interface: str = network_interface
        self.your_mac_address: str = self.base.get_interface_mac_address(self.network_interface)
        self.your_ipv6_link_address: str = self.base.get_interface_ipv6_link_address(self.network_interface)
    # endregion

    # region Analyze packet
    def _analyze_packet(self, packet: Dict) -> None:
        try:
            assert 'Ethernet' in packet.keys()
            assert 'IPv6' in packet.keys()
            assert 'ICMPv6' in packet.keys()
            assert 'type' in packet['ICMPv6'].keys()

            # region ICMPv6 multicast ping scan
            if not self.router_search:
                # 129 Type of ICMPv6 Echo (ping) reply
                assert packet['ICMPv6']['type'] == 129, \
                    'Not ICMPv6 Echo (ping) reply packet!'

                # Check ICMPv6 Echo (ping) reply identifier
                assert packet['ICMPv6']['identifier'] == self.icmpv6_identifier, \
                    'ICMPv6 Echo (ping) reply bad identifier'

                # Add MAC- and IPv6-address in result list
                self.results.append({'mac-address': packet['Ethernet']['source'],
                                     'ip-address': packet['IPv6']['source-ip']})
            # endregion

            # region Search IPv6 router
            if self.router_search:
                # 134 Type of ICMPv6 Router Advertisement
                assert packet['ICMPv6']['type'] == 134, 'Not ICMPv6 Router Advertisement packet!'

                # Save router information
                self.router_info['router_mac_address'] = packet['Ethernet']['source']
                self.router_info['router_ipv6_address'] = packet['IPv6']['source-ip']
                self.router_info['flags'] = hex(packet['ICMPv6']['flags'])
                self.router_info['router-lifetime'] = int(packet['ICMPv6']['router-lifetime'])
                self.router_info['reachable-time'] = int(packet['ICMPv6']['reachable-time'])
                self.router_info['retrans-timer'] = int(packet['ICMPv6']['retrans-timer'])

                for icmpv6_ra_option in packet['ICMPv6']['options']:
                    if icmpv6_ra_option['type'] == 3:
                        self.router_info['prefix'] = str(icmpv6_ra_option['value']['prefix']) + '/' + \
                                                     str(icmpv6_ra_option['value']['prefix-length'])
                    if icmpv6_ra_option['type'] == 5:
                        self.router_info['mtu'] = int(icmpv6_ra_option['value'], 16)
                    if icmpv6_ra_option['type'] == 25:
                        self.router_info['dns-server'] = str(icmpv6_ra_option['value']['address'])

                # Search router vendor
                self.router_info['vendor'] = \
                    self.base.get_vendor_by_mac_address(self.router_info['router_mac_address'])
            # endregion

        except AssertionError:
            pass
    # endregion

    # region Sniffer
    def _sniff(self) -> None:
        """
        Sniff ICMPv6 packets
        :return: None
        """

        # region ICMPv6 multicast ping scan
        if not self.router_search:
            self.raw_sniff.start(protocols=['Ethernet', 'IPv6', 'ICMPv6'],
                                 prn=self._analyze_packet,
                                 filters={'Ethernet': {'destination': self.your_mac_address},
                                          'IPv6': {'destination-ip': self.your_ipv6_link_address},
                                          'ICMPv6': {'type': 129}},
                                 network_interface=self.network_interface,
                                 scapy_filter='icmp6',
                                 scapy_lfilter=lambda eth: eth.dst == self.your_mac_address)
        # endregion

        # region Search IPv6 router
        if self.router_search:
            self.raw_sniff.start(protocols=['Ethernet', 'IPv6', 'ICMPv6'],
                                 prn=self._analyze_packet,
                                 filters={'Ethernet': {'destination': self.your_mac_address},
                                          'IPv6': {'destination-ip': self.your_ipv6_link_address},
                                          'ICMPv6': {'type': 134}},
                                 network_interface=self.network_interface,
                                 scapy_filter='icmp6',
                                 scapy_lfilter=lambda eth: eth.dst == self.your_mac_address)
        # endregion

    # endregion

    # region Sender
    def _send(self) -> None:
        """
        Send ICMPv6 packets
        :return: None
        """

        if self.router_search:
            request: bytes = self.icmpv6.make_router_solicit_packet(ethernet_src_mac=self.your_mac_address,
                                                                    ipv6_src=self.your_ipv6_link_address)

        else:
            request: bytes = self.icmpv6.make_echo_request_packet(ethernet_src_mac=self.your_mac_address,
                                                                  ethernet_dst_mac=self.target_mac_address,
                                                                  ipv6_src=self.your_ipv6_link_address,
                                                                  ipv6_dst='ff02::1',
                                                                  id=self.icmpv6_identifier)

        raw_send: RawSend = RawSend(network_interface=self.network_interface)
        raw_send.send(packet=request, count=self.retry_number, delay=0.1)
    # endregion

    # region Scanner
    def scan(self, timeout: int = 3, retry: int = 3, target_mac_address: Union[None, str] = None,
             check_vendor: bool = True, exit_on_failure: bool = True) -> List[Dict[str, str]]:
        """
        Find alive IPv6 hosts in local network with echo (ping) request packets
        :param timeout: Timeout in seconds (default: 3)
        :param retry: Retry number (default: 3)
        :param target_mac_address: Target MAC address (example: 192.168.0.1)
        :param check_vendor: Check vendor of hosts (default: True)
        :param exit_on_failure: Exit if alive IPv6 hosts in network not found (default: True)
        :return: List of alive hosts in network (example: [{'mac-address': '01:23:45:67:89:0a',
                                                            'ip-address': 'fe80::1234:5678:90ab:cdef',
                                                            'vendor': 'Apple, Inc.'}])
        """

        # region Clear lists with scan results
        self.results.clear()
        self.unique_results.clear()
        self.mac_addresses.clear()
        # endregion

        # region Set variables
        if target_mac_address is not None:
            self.base.mac_address_validation(mac_address=target_mac_address, exit_on_failure=True)
            self.target_mac_address = target_mac_address
        self.timeout = int(timeout)
        self.retry_number = int(retry)
        self.icmpv6_identifier = randint(1, 65535)
        # endregion

        # region Run _sniffer
        self.thread_manager.add_task(self._sniff)
        # endregion

        # region Run _sender
        self._send()
        # endregion

        # region Wait
        sleep(self.timeout)
        # endregion

        # region Unique results
        for index in range(len(self.results)):
            if self.results[index]['mac-address'] not in self.mac_addresses:
                self.unique_results.append(self.results[index])
                self.mac_addresses.append(self.results[index]['mac-address'])
        # endregion

        # region Get vendors
        if check_vendor:
            for result_index in range(len(self.unique_results)):
                self.unique_results[result_index]['vendor'] = \
                    self.base.get_vendor_by_mac_address(self.unique_results[result_index]['mac-address'])
        # endregion

        # region Return results
        if len(self.unique_results) == 0:
            if exit_on_failure:
                self.base.error_text('Could not found alive IPv6 hosts on interface: ' + self.network_interface)
                exit(1)
        return self.unique_results
        # endregion

    # endregion

    # region Search IPv6 router
    def search_router(self, timeout: int = 3, retry: int = 3,
                      exit_on_failure: bool = True) -> Dict[str, Union[int, str]]:
        """
        Search IPv6 router in network
        :param timeout: Timeout in seconds (default: 3)
        :param retry: Retry number (default: 3)
        :param exit_on_failure: Exit if IPv6 router in network not found (default: True)
        :return: IPv6 router information dictionary (example: {'router_mac_address': '01:23:45:67:89:0a',
                                                               'router_ipv6_address': 'fe80::1234:5678:90ab:cdef',
                                                               'flags': '0x0',
                                                               'router-lifetime': 0,
                                                               'reachable-time': 0,
                                                               'retrans-timer': 0,
                                                               'prefix': 'fd00::/64',
                                                               'vendor': 'D-Link International'})
        """

        # region Clear lists with scan results
        self.results.clear()
        self.unique_results.clear()
        self.mac_addresses.clear()
        # endregion

        # region Set variables
        self.router_search = True
        self.timeout = int(timeout)
        self.retry_number = int(retry)
        # endregion

        # region Run _sniffer
        self.thread_manager.add_task(self._sniff)
        # endregion

        # region Run _sender
        self._send()
        # endregion

        # region Wait
        sleep(self.timeout)
        # endregion

        # region Return IPv6 router information
        if len(self.router_info.keys()) == 0:
            if exit_on_failure:
                self.base.error_text('Could not found IPv6 Router on interface: ' + self.network_interface)
                exit(1)
        return self.router_info
        # endregion

    # endregion

# endregion
