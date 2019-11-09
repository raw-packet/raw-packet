#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
scanner.py: Scan local network
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Raw-packet modules
from raw_packet.Utils.network import RawEthernet, RawARP
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.base import Base
# endregion

# region Import libraries
from socket import socket, AF_PACKET, SOCK_RAW, htons, error
from ipaddress import IPv4Address
from sys import stdout
from time import sleep
from typing import Union, List, Dict
# endregion

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


# region class ARP scanner
class ArpScan:

    # region Set variables
    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    arp: RawARP = RawARP()

    rawSocket: socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))

    network_interface: Union[None, str] = None
    your_mac_address: Union[None, str] = None
    your_ip_address: Union[None, str] = None
    target_ip_address: Union[None, str] = None

    results: List[Dict[str, str]] = list()
    mac_addresses: List[str] = list()
    unique_results: List[Dict[str, str]] = list()

    retry_number: int = 3
    timeout: int = 5

    quit: bool = False
    # endregion

    # region Sniffer
    def _sniff(self) -> None:
        """
        Sniff ARP replies
        :return: None
        """
        while True:
            try:
                packets = self.rawSocket.recvfrom(2048)

                for packet in packets:

                    # Parse Ethernet header
                    ethernet_header = packet[0:14]
                    ethernet_header_dict = self.eth.parse_header(ethernet_header)

                    # Success parse Ethernet header
                    assert ethernet_header_dict is not None, 'Not Ethernet packet!'

                    # 2054 - Type of ARP packet (0x0806)
                    assert ethernet_header_dict['type'] == 2054, 'Not ARP packet!'

                    # Destination MAC address is your MAC address
                    assert ethernet_header_dict['destination'] == self.your_mac_address, 'Not your ARP reply packet!'

                    # Parse ARP packet
                    arp_header = packet[14:42]
                    arp_header_dict = self.arp.parse_packet(arp_header)

                    # Success parse ARP packet
                    assert arp_header_dict is not None, 'Could not parse ARP packet!'

                    # ARP opcode == 2 (2 - ARP reply)
                    assert arp_header_dict['opcode'] == 2, 'Not ARP reply packet!'

                    # ARP target MAC address is your MAC address
                    assert arp_header_dict['target-mac'] == self.your_mac_address, 'Not your ARP reply packet!'

                    # ARP target IP address is your IP address
                    assert arp_header_dict['target-ip'] == self.your_ip_address, 'Not your ARP reply packet!'

                    # Parameter Target IP address is None
                    if self.target_ip_address is None:
                        self.results.append({
                            'mac-address': arp_header_dict['sender-mac'],
                            'ip-address': arp_header_dict['sender-ip']
                        })

                    # Parameter Target IP address is Set
                    else:
                        if arp_header_dict['sender-ip'] == self.target_ip_address:
                            self.results.append({
                                'mac-address': arp_header_dict['sender-mac'],
                                'ip-address': arp_header_dict['sender-ip']
                            })

            # Exception
            except AssertionError:
                pass
    # endregion

    # region Sender
    def _send(self) -> None:
        """
        Send ARP requests
        :return: None
        """
        arp_requests: List[bytes] = list()

        self.your_mac_address = self.base.get_interface_mac_address(self.network_interface)
        self.your_ip_address = self.base.get_interface_ip_address(self.network_interface)

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

        try:
            send_socket: socket = socket(AF_PACKET, SOCK_RAW)
            send_socket.bind((self.network_interface, 0))

            number_of_requests: int = len(arp_requests) * int(self.retry_number)
            index_of_request: int = 0
            percent_complete: int = 0

            for _ in range(int(self.retry_number)):
                for arp_request in arp_requests:
                    send_socket.send(arp_request)
                    if not self.quit:
                        index_of_request += 1
                        new_percent_complete = int(float(index_of_request)/float(number_of_requests) * 100)
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
            send_socket.close()

        except error as e:
            self.base.print_error('Exception: ', str(e))
            exit(1)

    # endregion

    # region Scanner
    def scan(self, network_interface: str = 'eth0', timeout: int = 3, retry: int = 3,
             target_ip_address: Union[None, str] = None, check_vendor: bool = True,
             exclude_ip_addresses: Union[None, List[str]] = None, exit_on_failure: bool = True,
             show_scan_percentage: bool = True) -> List[Dict[str, str]]:
        """
        ARP scan on network interface
        :param network_interface: Network interface name (example: 'eth0')
        :param timeout: Timeout in seconds (default: 3)
        :param retry: Retry number (default: 3)
        :param target_ip_address: Target IPv4 address (example: 192.168.0.1)
        :param check_vendor: Check vendor of hosts
        :param exclude_ip_addresses: Exclude IPv4 address list (example: ['192.168.0.1','192.168.0.2'])
        :param exit_on_failure: Exit if alive hosts in network not found
        :param show_scan_percentage: Show ARP scan progress percentage
        :return: Result list of alive hosts (example: [{'mac-address': '01:23:45:67:89:0a', 'ip-address': '192.168.0.1'}])
        """
        try:
            # region Clear lists with scan results
            self.results.clear()
            self.unique_results.clear()
            self.mac_addresses.clear()
            # endregion
    
            # region Set variables
            self.quit = not show_scan_percentage
            self.target_ip_address = target_ip_address
            self.network_interface = network_interface
            self.timeout = int(timeout)
            self.retry_number = int(retry)
            # endregion
    
            # region Run _sniffer
            tm = ThreadManager(2)
            tm.add_task(self._sniff)
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
            
        except KeyboardInterrupt:
            self.base.print_info('Exit')
            exit(0)
        
        if len(self.unique_results) == 0:
            if exit_on_failure:
                self.base.print_error('Could not find allive hosts on interface: ', self.network_interface)
                exit(1)
    
        return self.unique_results
    # endregion

    # region Get MAC address
    def get_mac_address(self, network_interface: str = 'eth0', target_ip_address: str = '192.168.0.1',
                        timeout: int = 5, retry: int = 5, exit_on_failure: bool = True,
                        show_scan_percentage: bool = True) -> str:
        """
        Get MAC address of IP address on network interface
        :param network_interface: Network interface name (example: 'eth0')
        :param timeout: Timeout in seconds (default: 3)
        :param retry: Retry number (default: 3)
        :param target_ip_address: Target IPv4 address (example: 192.168.0.1)
        :param exit_on_failure: Exit if MAC address of target IP address not found
        :param show_scan_percentage: Show ARP scan progress percentage
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
            self.network_interface = network_interface
            self.timeout = int(timeout)
            self.retry_number = int(retry)
            # endregion

            # region Run _sniffer
            tm = ThreadManager(2)
            tm.add_task(self._sniff)
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
