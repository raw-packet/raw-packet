# region Description
"""
icmpv6_router_search.py: ICMPv6 Search IPv6 Router
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
from typing import Union, Dict

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
class ICMPv6RouterSearch:

    # region Set variables
    _base: Base = Base()
    _icmpv6: RawICMPv6 = RawICMPv6()
    _raw_sniff: RawSniff = RawSniff()
    _thread_manager: ThreadManager = ThreadManager(2)

    _your: Dict[str, Union[None, str]] = {'network-interface': None, 'mac-address': None, 'ipv6-link-address': None}

    _retry_number: int = 3
    _timeout: int = 3

    _router_info: Union[None, Dict[str, Union[int, str]]] = None
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

            # 134 Type of ICMPv6 Router Advertisement
            assert packet['ICMPv6']['type'] == 134, 'Not ICMPv6 Router Advertisement packet!'

            # Save router information
            self._router_info = dict()
            self._router_info['router_mac_address'] = packet['Ethernet']['source']
            self._router_info['router_ipv6_address'] = packet['IPv6']['source-ip']
            self._router_info['flags'] = hex(packet['ICMPv6']['flags'])
            self._router_info['router-lifetime'] = int(packet['ICMPv6']['router-lifetime'])
            self._router_info['reachable-time'] = int(packet['ICMPv6']['reachable-time'])
            self._router_info['retrans-timer'] = int(packet['ICMPv6']['retrans-timer'])

            for icmpv6_ra_option in packet['ICMPv6']['options']:
                if icmpv6_ra_option['type'] == 3:
                    self._router_info['prefix'] = str(icmpv6_ra_option['value']['prefix']) + '/' + \
                                                  str(icmpv6_ra_option['value']['prefix-length'])
                if icmpv6_ra_option['type'] == 5:
                    self._router_info['mtu'] = int(icmpv6_ra_option['value'], 16)
                if icmpv6_ra_option['type'] == 25:
                    self._router_info['dns-server'] = str(icmpv6_ra_option['value']['address'])

            # Search router vendor
            self._router_info['vendor'] = \
                self._base.get_vendor_by_mac_address(self._router_info['router_mac_address'])

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
        self._raw_sniff.start(protocols=['Ethernet', 'IPv6', 'ICMPv6'],
                              prn=self._analyze_packet,
                              filters={'ICMPv6': {'type': 134}},
                              network_interface=self._your['network-interface'],
                              scapy_filter='icmp6')
    # endregion

    # region Sender
    def _send(self) -> None:
        """
        Send ICMPv6 packets
        :return: None
        """
        request: bytes = self._icmpv6.make_router_solicit_packet(ethernet_src_mac=self._your['mac-address'],
                                                                 ipv6_src=self._your['ipv6-link-address'])
        self._raw_send.send_packet(packet=request, count=self._retry_number, delay=0.1)
    # endregion

    # region Search IPv6 router
    def search(self,
               timeout: int = 3,
               retry: int = 3,
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

        # region Set variables
        self._timeout = int(timeout)
        self._retry_number = int(retry)
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

        # region Return IPv6 router information
        if self._router_info is None:
            if exit_on_failure:
                self._base.error_text('Could not found IPv6 Router on interface: ' + self._your['network-interface'])
                exit(1)
        return self._router_info
        # endregion

    # endregion

# endregion
