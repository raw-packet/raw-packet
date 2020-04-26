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
from raw_packet.Utils.network import RawEthernet, RawARP, RawSniff, RawSend
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.base import Base
# endregion

# region Import libraries
from socket import inet_aton
from ipaddress import IPv4Address
from sys import stdout
from time import sleep
from typing import Union, List, Dict
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


# region class ARP scanner
class ArpScan:

    # region Set variables
    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    arp: RawARP = RawARP()
    raw_sniff: RawSniff = RawSniff()
    thread_manager: ThreadManager = ThreadManager(2)

    network_interface: Union[None, str] = None
    your_mac_address: Union[None, str] = None
    your_ip_address: Union[None, str] = None
    target_ip_address: Union[None, str] = None

    results: List[Dict[str, str]] = list()
    mac_addresses: List[str] = list()
    unique_results: List[Dict[str, str]] = list()
    sorted_results: List[Dict[str, str]] = list()

    retry_number: int = 3
    timeout: int = 5

    quit: bool = False
    # endregion

    # region Init
    def __init__(self, network_interface: str) -> None:
        """
        Init
        :param network_interface: Network interface name (example: 'eth0')
        """
        self.network_interface: str = network_interface
        self.your_mac_address: str = self.base.get_interface_mac_address(self.network_interface)
        self.your_ip_address: str = self.base.get_interface_ip_address(self.network_interface)
    # endregion

    # region Analyze packet
    def _analyze_packet(self, packet: Dict[str, Dict[str, str]]) -> None:
        """
        Analyze ARP reply
        :param packet: Parsed ARP reply
        :return: None
        """

        try:
            assert 'ARP' in packet.keys()
            assert 'sender-mac' in packet['ARP'].keys()
            assert 'sender-ip' in packet['ARP'].keys()
            assert 'target-mac' in packet['ARP'].keys()
            assert 'target-ip' in packet['ARP'].keys()
            assert packet['ARP']['target-mac'] == self.your_mac_address
            assert packet['ARP']['target-ip'] == self.your_ip_address

            # region Parameter Target IP address is None
            if self.target_ip_address is None:
                self.results.append({
                    'mac-address': packet['ARP']['sender-mac'],
                    'ip-address': packet['ARP']['sender-ip']
                })
            # endregion

            # region Parameter Target IP address is Set
            else:
                if packet['ARP']['sender-ip'] == self.target_ip_address:
                    self.results.append({
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
        self.raw_sniff.start(protocols=['Ethernet', 'ARP'],
                             prn=self._analyze_packet,
                             filters={'Ethernet': {'destination': self.your_mac_address},
                                      'ARP': {'opcode': 2,
                                              'target-mac': self.your_mac_address,
                                              'target-ip': self.your_ip_address}},
                             network_interface=self.network_interface,
                             scapy_filter='arp',
                             scapy_lfilter=lambda eth: eth.dst == self.your_mac_address)
    # endregion

    # region Sender
    def _send(self) -> None:
        """
        Send ARP requests
        :return: None
        """
        arp_requests: List[bytes] = list()

        first_ip_address = self.base.get_first_ip_on_interface(self.network_interface)
        last_ip_address = self.base.get_last_ip_on_interface(self.network_interface)

        if self.target_ip_address is not None:
            if self.base.ip_address_in_range(self.target_ip_address, first_ip_address, last_ip_address):
                first_ip_address = self.target_ip_address
                last_ip_address = self.target_ip_address
            else:
                self.base.print_error('Bad target IP address: ', self.target_ip_address,
                                      '; Target IP address must be in range: ',
                                      first_ip_address + ' - ' + last_ip_address)
                exit(1)

        index: int = 0
        while True:
            current_ip_address: str = str(IPv4Address(first_ip_address) + index)
            index += 1
            if IPv4Address(current_ip_address) > IPv4Address(last_ip_address):
                break

            arp_request: bytes = self.arp.make_request(ethernet_src_mac=self.your_mac_address,
                                                       ethernet_dst_mac='ff:ff:ff:ff:ff:ff',
                                                       sender_mac=self.your_mac_address,
                                                       sender_ip=self.your_ip_address,
                                                       target_mac='00:00:00:00:00:00',
                                                       target_ip=current_ip_address)
            arp_requests.append(arp_request)

        raw_send: RawSend = RawSend(network_interface=self.network_interface)

        number_of_requests: int = len(arp_requests) * int(self.retry_number)
        index_of_request: int = 0
        percent_complete: int = 0

        for _ in range(int(self.retry_number)):
            for arp_request in arp_requests:
                raw_send.send(arp_request)
                if not self.quit:
                    index_of_request += 1
                    new_percent_complete = int(float(index_of_request) / float(number_of_requests) * 100)
                    if new_percent_complete > percent_complete:
                        stdout.write('\r')
                        stdout.write(self.base.c_info + 'Interface: ' +
                                     self.base.info_text(self.network_interface) + ' ARP scan percentage: ' +
                                     self.base.info_text(str(new_percent_complete) + '%'))
                        stdout.flush()
                        sleep(0.01)
                        percent_complete = new_percent_complete
        if not self.quit:
            stdout.write('\n')

    # endregion

    # region Scanner
    def scan(self, timeout: int = 3, retry: int = 3,
             target_ip_address: Union[None, str] = None, check_vendor: bool = True,
             exclude_ip_addresses: Union[None, List[str]] = None, exit_on_failure: bool = True,
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
            self.results.clear()
            self.unique_results.clear()
            self.sorted_results.clear()
            self.mac_addresses.clear()
            # endregion
    
            # region Set variables
            self.quit = not show_scan_percentage
            self.target_ip_address = target_ip_address
            self.timeout = int(timeout)
            self.retry_number = int(retry)
            # endregion
    
            # region Run _sniffer
            self.thread_manager.add_task(self._sniff)
            # endregion
    
            # region Run sender
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

            # region Exclude IP addresses
            if exclude_ip_addresses is not None:
                self.results = self.unique_results
                self.unique_results = list()
                for index in range(len(self.results)):
                    if self.results[index]['ip-address'] not in exclude_ip_addresses:
                        self.unique_results.append(self.results[index])
                self.results = list()
            # endregion
    
            # region Get vendors
            if check_vendor:
                for result_index in range(len(self.unique_results)):
                    self.unique_results[result_index]['vendor'] = \
                        self.base.get_vendor_by_mac_address(self.unique_results[result_index]['mac-address'])
            # endregion

            # region Sort by IP address
            self.sorted_results = sorted(self.unique_results, key=lambda ip: inet_aton(ip['ip-address']))
            # endregion
            
        except KeyboardInterrupt:
            self.base.print_info('Exit')
            exit(0)
        
        if len(self.unique_results) == 0:
            if exit_on_failure:
                self.base.print_error('Could not find allive hosts on interface: ', self.network_interface)
                exit(1)
    
        return self.sorted_results
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
        result_mac_address = 'ff:ff:ff:ff:ff:ff'
        # endregion
        try: 
            # region Clear lists with scan results
            self.results.clear()
            self.unique_results.clear()
            self.mac_addresses.clear()
            # endregion

            # region Set variables
            self.quit = not show_scan_percentage
            self.target_ip_address = target_ip_address
            self.timeout = int(timeout)
            self.retry_number = int(retry)
            # endregion

            # region Run _sniffer
            self.thread_manager.add_task(self._sniff)
            # endregion

            # region Run sender
            self._send()
            # endregion

            # region Wait
            sleep(self.timeout)
            # endregion

            # region Return
            if 'mac-address' in self.results[0].keys():
                result_mac_address = self.results[0]['mac-address']
            # endregion

        except IndexError:
            pass

        except KeyboardInterrupt:
            self.base.print_info('Exit')
            exit(0)
        
        if result_mac_address == 'ff:ff:ff:ff:ff:ff':
            if exit_on_failure:
                self.base.print_error('Could not find MAC address of IP address: ', target_ip_address)
                exit(1)
        
        return result_mac_address
    # endregion

# endregion
