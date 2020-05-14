# region Description
"""
icmpv6_scanner.py: ICMPv6 Scan local network
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import RawICMPv6, RawSniff, RawSend
from raw_packet.Utils.tm import ThreadManager
from time import sleep
from random import randint
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
# endregion


# region class ICMPv6 scanner
class ICMPv6Scan:

    # region Set variables
    _base: Base = Base()
    _icmpv6: RawICMPv6 = RawICMPv6()
    _raw_sniff: RawSniff = RawSniff()
    _thread_manager: ThreadManager = ThreadManager(2)

    _your: Dict[str, Union[None, str]] = {'network-interface': None, 'mac-address': None, 'ipv6-link-address': None}
    _target: Dict[str, Union[None, str]] = {'ipv6-address': None, 'mac-address': 'ff:ff:ff:ff:ff:ff', 'vendor': None}

    _results: List[Dict[str, str]] = list()
    _unique_results: List[Dict[str, str]] = list()
    _mac_addresses: List[str] = list()
    
    _retry_number: int = 3
    _timeout: int = 3

    _icmpv6_identifier: int = 0
    # endregion

    # region Init
    def __init__(self, network_interface: str) -> None:
        """
        Init
        :param network_interface: Network interface name (example: 'eth0')
        """
        self._your = self._base.get_interface_settings(interface_name=network_interface,
                                                       required_parameters=['mac-address',
                                                                            'ipv6-link-address'])
        self._raw_send: RawSend = RawSend(network_interface=network_interface)
    # endregion

    # region Analyze packet
    def _analyze_packet(self, packet: Dict) -> None:
        try:
            assert 'Ethernet' in packet.keys()
            assert 'IPv6' in packet.keys()
            assert 'ICMPv6' in packet.keys()
            assert 'type' in packet['ICMPv6'].keys()
            assert 'identifier' in packet['ICMPv6'].keys()

            # 129 Type of ICMPv6 Echo (ping) reply
            assert packet['ICMPv6']['type'] == 129, \
                'Not ICMPv6 Echo (ping) reply packet!'

            # Check ICMPv6 Echo (ping) reply identifier
            assert packet['ICMPv6']['identifier'] == self._icmpv6_identifier, \
                'ICMPv6 Echo (ping) reply bad identifier'

            # Add MAC- and IPv6-address in result list
            self._results.append({'mac-address': packet['Ethernet']['source'],
                                  'ip-address': packet['IPv6']['source-ip']})

        except AssertionError:
            pass
    # endregion

    # region Sniffer
    def _sniff(self) -> None:
        """
        Sniff ICMPv6 packets
        :return: None
        """
        self._raw_sniff.start(protocols=['Ethernet', 'IPv6', 'ICMPv6'],
                              prn=self._analyze_packet,
                              filters={'Ethernet': {'destination': self._your['mac-address']},
                                       'IPv6': {'destination-ip': self._your['ipv6-link-address']},
                                       'ICMPv6': {'type': 129}},
                              network_interface=self._your['network-interface'],
                              scapy_filter='icmp6',
                              scapy_lfilter=lambda eth: eth.dst == self._your['mac-address'])
    # endregion

    # region Sender
    def _send(self) -> None:
        """
        Send ICMPv6 packets
        :return: None
        """
        request: bytes = self._icmpv6.make_echo_request_packet(ethernet_src_mac=self._your['mac-address'],
                                                               ethernet_dst_mac=self._target['mac-address'],
                                                               ipv6_src=self._your['ipv6-link-address'],
                                                               ipv6_dst='ff02::1',
                                                               id=self._icmpv6_identifier)
        self._raw_send.send_packet(packet=request, count=self._retry_number, delay=0.3)
    # endregion

    # region Scanner
    def scan(self,
             timeout: int = 3,
             retry: int = 3,
             target_mac_address: Union[None, str] = None,
             check_vendor: bool = True,
             exit_on_failure: bool = True,
             exclude_ipv6_addresses: List[str] = []) -> List[Dict[str, str]]:
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
        self._results.clear()
        self._unique_results.clear()
        self._mac_addresses.clear()
        # endregion

        # region Set variables
        if target_mac_address is not None:
            self._base.mac_address_validation(mac_address=target_mac_address, exit_on_failure=True)
            self._target['mac-address'] = target_mac_address
        self._timeout = int(timeout)
        self._retry_number = int(retry)
        self._icmpv6_identifier = randint(1, 65535)
        # endregion

        # region Run _sniffer
        self._thread_manager.add_task(self._sniff)
        # endregion

        # region Run _sender
        self._send()
        # endregion

        # region Wait
        sleep(self._timeout)
        # endregion

        # region Unique results
        for index in range(len(self._results)):
            if self._results[index]['mac-address'] not in self._mac_addresses:
                self._unique_results.append(self._results[index])
                self._mac_addresses.append(self._results[index]['mac-address'])
        # endregion

        # region Get vendors
        if check_vendor:
            for result_index in range(len(self._unique_results)):
                self._unique_results[result_index]['vendor'] = \
                    self._base.get_vendor_by_mac_address(self._unique_results[result_index]['mac-address'])
        # endregion

        # region Exclude IPv6 addresses
        if len(exclude_ipv6_addresses) > 0:
            results: List[Dict[str, str]] = list()
            for unique_result in self._unique_results:
                if unique_result['ip-address'] not in exclude_ipv6_addresses:
                    results.append(unique_result)
            self._unique_results = results
        # endregion

        # region Return results
        if len(self._unique_results) == 0:
            if exit_on_failure:
                self._base.error_text('Could not found alive IPv6 hosts on interface: ' +
                                      self._your['network-interface'])
                exit(1)
        return self._unique_results
        # endregion

    # endregion

# endregion
