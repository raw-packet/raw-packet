# region Description
"""
arp_scanner.py: ARP Scan local network
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.network import RawARP, RawSniff, RawSend
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.base import Base
from socket import inet_aton
from ipaddress import IPv4Address
from sys import stdout
from time import sleep
from typing import Union, List, Dict
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


# region class ARP scanner
class ArpScan:

    # region Variables
    _base: Base = Base()
    _arp: RawARP = RawARP()
    _raw_sniff: RawSniff = RawSniff()
    _thread_manager: ThreadManager = ThreadManager(2)

    _your: Dict[str, Union[None, str]] = {'network-interface': None, 'mac-address': None}
    _target: Dict[str, Union[None, str]] = {'ipv4-address': None, 'mac-address': None}

    _results: List[Dict[str, str]] = list()
    _mac_addresses: List[str] = list()
    _unique_results: List[Dict[str, str]] = list()
    _sorted_results: List[Dict[str, str]] = list()

    _retry_number: int = 3
    _timeout: int = 5
    _quit: bool = False
    # endregion

    # region Init
    def __init__(self, network_interface: str) -> None:
        """
        Init
        :param network_interface: Network interface name (example: 'eth0')
        """
        self._your = self._base.get_interface_settings(interface_name=network_interface,
                                                       required_parameters=['mac-address',
                                                                            'ipv4-address',
                                                                            'first-ipv4-address',
                                                                            'last-ipv4-address'])
        self._raw_send: RawSend = RawSend(network_interface=network_interface)

    # endregion

    # region Analyze packet
    def _analyze_packet(self, packet: Dict[str, Dict[str, str]]) -> None:
        """
        Analyze ARP reply
        :param packet: Parsed ARP reply
        :return: None
        """

        try:

            # region Asserts
            assert 'ARP' in packet.keys()
            assert 'sender-mac' in packet['ARP'].keys()
            assert 'sender-ip' in packet['ARP'].keys()
            assert 'target-mac' in packet['ARP'].keys()
            assert 'target-ip' in packet['ARP'].keys()
            assert packet['ARP']['target-mac'] == self._your['mac-address']
            assert packet['ARP']['target-ip'] == self._your['ipv4-address']
            # endregion

            # region Parameter Target IPv4 address is None
            if self._target['ipv4-address'] is None:
                self._results.append({
                    'mac-address': packet['ARP']['sender-mac'],
                    'ip-address': packet['ARP']['sender-ip']
                })
            # endregion

            # region Parameter Target IPv4 address is Set
            else:
                if packet['ARP']['sender-ip'] == self._target['ipv4-address']:
                    self._results.append({
                        'mac-address': packet['ARP']['sender-mac'],
                        'ip-address': packet['ARP']['sender-ip']
                    })
            # endregion

        except AssertionError:
            pass

    # endregion

    # region Sniffer
    def _sniff(self) -> None:
        """
        Sniff ARP replies
        :return: None
        """
        self._raw_sniff.start(protocols=['Ethernet', 'ARP'],
                              prn=self._analyze_packet,
                              filters={'Ethernet': {'destination': self._your['mac-address']},
                                       'ARP': {'opcode': 2,
                                               'target-mac': self._your['mac-address'],
                                               'target-ip': self._your['ipv4-address']}},
                              network_interface=self._your['network-interface'],
                              scapy_filter='arp',
                              scapy_lfilter=lambda eth: eth.dst == self._your['mac-address'])
    # endregion

    # region Sender
    def _send(self) -> None:
        """
        Send ARP requests
        :return: None
        """
        arp_requests: List[bytes] = list()

        if self._target['ipv4-address'] is not None:
            first_ip_address = self._target['ipv4-address']
            last_ip_address = self._target['ipv4-address']
        else:
            first_ip_address = self._your['first-ipv4-address']
            last_ip_address = self._your['last-ipv4-address']

        index: int = 0
        while True:
            current_ip_address: str = str(IPv4Address(first_ip_address) + index)
            index += 1
            if IPv4Address(current_ip_address) > IPv4Address(last_ip_address):
                break

            arp_request: bytes = self._arp.make_request(ethernet_src_mac=self._your['mac-address'],
                                                        ethernet_dst_mac='ff:ff:ff:ff:ff:ff',
                                                        sender_mac=self._your['mac-address'],
                                                        sender_ip=self._your['ipv4-address'],
                                                        target_mac='00:00:00:00:00:00',
                                                        target_ip=current_ip_address)
            arp_requests.append(arp_request)

        number_of_requests: int = len(arp_requests) * int(self._retry_number)
        index_of_request: int = 0
        percent_complete: int = 0

        for _ in range(int(self._retry_number)):
            for arp_request in arp_requests:
                self._raw_send.send(arp_request)
                if not self._quit:
                    index_of_request += 1
                    new_percent_complete = int(float(index_of_request) / float(number_of_requests) * 100)
                    if new_percent_complete > percent_complete:
                        stdout.write('\r')
                        stdout.write(self._base.c_info + 'Interface: ' +
                                     self._base.info_text(self._your['network-interface']) + ' ARP scan percentage: ' +
                                     self._base.info_text(str(new_percent_complete) + '%'))
                        stdout.flush()
                        sleep(0.01)
                        percent_complete = new_percent_complete
        if not self._quit:
            stdout.write('\n')
    # endregion

    # region Check target IPv4 address
    def _check_target_ip_address(self, target_ip_address: Union[None, str]) -> Union[None, str]:
        try:
            if target_ip_address is not None:
                assert self._base.ip_address_in_range(target_ip_address,
                                                      self._your['first-ipv4-address'],
                                                      self._your['last-ipv4-address']), \
                    'Bad target IPv4 address: ' + \
                    self._base.error_text(target_ip_address) + \
                    '; target IPv4 address must be in range: ' + \
                    self._base.info_text(self._your['first-ipv4-address'] + ' - ' + self._your['last-ipv4-address'])
                return target_ip_address
            else:
                return None
        except AssertionError as Error:
            self._base.print_error(Error.args[0])
            exit(1)
    # endregion

    # region Scanner
    def scan(self, timeout: int = 3, retry: int = 3,
             target_ip_address: Union[None, str] = None,
             check_vendor: bool = True,
             exclude_ip_addresses: Union[None, List[str]] = None,
             exit_on_failure: bool = True,
             show_scan_percentage: bool = True) -> List[Dict[str, str]]:
        """
        ARP scan on network interface
        :param timeout: Timeout in seconds (default: 3)
        :param retry: Retry number (default: 3)
        :param target_ip_address: Target IPv4 address (example: 192.168.0.1)
        :param check_vendor: Check vendor of hosts (default: True)
        :param exclude_ip_addresses: Exclude IPv4 address list (example: ['192.168.0.1','192.168.0.2'])
        :param exit_on_failure: Exit if alive hosts in network not found (default: True)
        :param show_scan_percentage: Show ARP scan progress percentage (default: True)
        :return: Result list of alive hosts (example: [{'mac-address': '01:23:45:67:89:0a',
                                                        'ip-address': '192.168.0.1',
                                                        'vendor': 'Raspberry Pi Foundation'}])
        """
        try:
            # region Clear lists with scan results
            self._results.clear()
            self._unique_results.clear()
            self._sorted_results.clear()
            self._mac_addresses.clear()
            # endregion

            # region Set variables
            self._quit = not show_scan_percentage
            self._target['ipv4-address'] = self._check_target_ip_address(target_ip_address)
            self._timeout = int(timeout)
            self._retry_number = int(retry)
            # endregion

            # region Run _sniffer
            self._thread_manager.add_task(self._sniff)
            # endregion

            # region Run sender
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

            # region Exclude IP addresses
            if exclude_ip_addresses is not None:
                self._results = self._unique_results
                self._unique_results = list()
                for index in range(len(self._results)):
                    if self._results[index]['ip-address'] not in exclude_ip_addresses:
                        self._unique_results.append(self._results[index])
                self._results = list()
            # endregion

            # region Get vendors
            if check_vendor:
                for result_index in range(len(self._unique_results)):
                    self._unique_results[result_index]['vendor'] = \
                        self._base.get_vendor_by_mac_address(self._unique_results[result_index]['mac-address'])
            # endregion

            # region Sort by IP address
            self._sorted_results = sorted(self._unique_results, key=lambda ip: inet_aton(ip['ip-address']))
            # endregion

        except KeyboardInterrupt:
            self._base.print_info('Exit')
            exit(0)

        if len(self._unique_results) == 0:
            if exit_on_failure:
                self._base.print_error('Could not find allive hosts on interface: ', self._your['network-interface'])
                exit(1)

        return self._sorted_results

    # endregion

    # region Get MAC address
    def get_mac_address(self, target_ip_address: str = '192.168.0.1',
                        timeout: int = 5, retry: int = 5, exit_on_failure: bool = True,
                        show_scan_percentage: bool = True) -> str:
        """
        Get MAC address of IP address on network interface
        :param timeout: Timeout in seconds (default: 3)
        :param retry: Retry number (default: 3)
        :param target_ip_address: Target IPv4 address (example: 192.168.0.1)
        :param exit_on_failure: Exit if MAC address of target IP address not found (default: True)
        :param show_scan_percentage: Show ARP scan progress percentage (default: True)
        :return: MAC address of target IP address (example: '01:23:45:67:89:0a')
        """

        # region Set result MAC address value
        result_mac_address: str = 'ff:ff:ff:ff:ff:ff'
        # endregion

        try:
            # region Clear lists with scan results
            self._results.clear()
            self._unique_results.clear()
            self._mac_addresses.clear()
            # endregion

            # region Set variables
            self._quit = not show_scan_percentage
            self._target['ipv4-address'] = self._check_target_ip_address(target_ip_address)
            self._timeout = int(timeout)
            self._retry_number = int(retry)
            # endregion

            # region Run _sniffer
            self._thread_manager.add_task(self._sniff)
            # endregion

            # region Run sender
            self._send()
            # endregion

            # region Wait
            sleep(self._timeout)
            # endregion

            # region Return
            if 'mac-address' in self._results[0].keys():
                result_mac_address = self._results[0]['mac-address']
            # endregion

        except IndexError:
            pass

        except KeyboardInterrupt:
            self._base.print_info('Exit')
            exit(0)

        if result_mac_address == 'ff:ff:ff:ff:ff:ff':
            if exit_on_failure:
                self._base.print_error('Could not find MAC address of IP address: ', target_ip_address)
                exit(1)

        return result_mac_address
    # endregion

# endregion
