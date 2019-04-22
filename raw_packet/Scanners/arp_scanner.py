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
from raw_packet.Utils.network import Ethernet_raw, ARP_raw
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Utils.base import Base
# endregion

# region Import libraries
from socket import socket, AF_PACKET, SOCK_RAW, htons
from ipaddress import IPv4Address
from sys import stdout
from time import sleep
# endregion

# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.0.4'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region class ARP scanner
class ArpScan:

    # region Set variables
    base = None
    eth = None
    arp = None

    rawSocket = None

    network_interface = None
    your_mac_address = None
    your_ip_address = None
    target_ip_address = None

    results = None
    unique_results = None

    mac_addresses = None

    mac_prefixes_file = None
    vendor_list = None

    retry_number = 0
    timeout = 0
    # endregion

    # region Init
    def __init__(self):
        self.base = Base()
        self.eth = Ethernet_raw()
        self.arp = ARP_raw()
        self.rawSocket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
        self.results = []
        self.unique_results = []
        self.mac_addresses = []

        self.mac_prefixes_file = "mac-prefixes.txt"
        self.vendor_list = []

        self.retry_number = 3
        self.timeout = 0
    # endregion

    # region Sniffer
    def sniff(self):
        while True:
            packets = self.rawSocket.recvfrom(2048)

            for packet in packets:

                # Parse Ethernet header
                ethernet_header = packet[0:14]
                ethernet_header_dict = self.eth.parse_header(ethernet_header)

                # Success parse Ethernet header
                if ethernet_header_dict is not None:

                    # 2054 - Type of ARP packet (0x0806)
                    if ethernet_header_dict['type'] == 2054:

                        # Destination MAC address is your MAC address
                        if ethernet_header_dict['destination'] == self.your_mac_address:

                            # Parse ARP packet
                            arp_header = packet[14:42]
                            arp_header_dict = self.arp.parse_packet(arp_header)

                            # Success parse ARP packet
                            if arp_header_dict is not None:

                                # ARP opcode == 2 (2 - ARP reply)
                                if arp_header_dict['opcode'] == 2:

                                    # ARP target MAC address is your MAC address
                                    if arp_header_dict['target-mac'] == self.your_mac_address:

                                        # ARP target IP address is your IP address
                                        if arp_header_dict['target-ip'] == self.your_ip_address:

                                            # Parameter Target IP address is None
                                            if self.target_ip_address is None:
                                                self.results.append({
                                                    "mac-address": arp_header_dict['sender-mac'],
                                                    "ip-address": arp_header_dict['sender-ip']
                                                })

                                            # Parameter Target IP address is Set
                                            else:
                                                if arp_header_dict['sender-ip'] == self.target_ip_address:
                                                    self.results.append({
                                                        "mac-address": arp_header_dict['sender-mac'],
                                                        "ip-address": arp_header_dict['sender-ip']
                                                    })

    # endregion

    # region Sender
    def send(self):
        arp_requests = []

        self.your_mac_address = self.base.get_netiface_mac_address(self.network_interface)
        self.your_ip_address = self.base.get_netiface_ip_address(self.network_interface)

        first_ip_address = str(IPv4Address(unicode(self.base.get_netiface_first_ip(self.network_interface))) - 1)
        last_ip_address = str(IPv4Address(unicode(self.base.get_netiface_last_ip(self.network_interface))) + 1)

        if self.target_ip_address is not None:
            if self.base.ip_address_in_range(self.target_ip_address, first_ip_address, last_ip_address):
                first_ip_address = self.target_ip_address
                last_ip_address = self.target_ip_address
            else:
                self.base.print_error("Bad target IP address: ", self.target_ip_address,
                                      "; Target IP address must be in range: ",
                                      first_ip_address + " - " + last_ip_address)
                exit(1)

        index = 0
        while True:
            current_ip_address = str(IPv4Address(unicode(first_ip_address)) + index)
            index += 1

            if IPv4Address(unicode(current_ip_address)) > IPv4Address(unicode(last_ip_address)):
                break
            else:
                arp_request = self.arp.make_request(ethernet_src_mac=self.your_mac_address,
                                                    ethernet_dst_mac="ff:ff:ff:ff:ff:ff",
                                                    sender_mac=self.your_mac_address,
                                                    sender_ip=self.your_ip_address,
                                                    target_mac="00:00:00:00:00:00",
                                                    target_ip=current_ip_address)
                arp_requests.append(arp_request)

        send_socket = socket(AF_PACKET, SOCK_RAW)
        send_socket.bind((self.network_interface, 0))

        number_of_requests = len(arp_requests) * int(self.retry_number)
        index_of_request = 0
        percent_complete = 0

        for _ in range(int(self.retry_number)):
            for arp_request in arp_requests:
                send_socket.send(arp_request)
                index_of_request += 1
                new_percent_complete = int(float(index_of_request)/float(number_of_requests) * 100)
                if new_percent_complete > percent_complete:
                    stdout.write('\r')
                    stdout.write(self.base.c_info + 'Scan percentage: ' +
                                 self.base.cINFO + str(new_percent_complete) + '%' + self.base.cEND)
                    stdout.flush()
                    sleep(0.01)
                    percent_complete = new_percent_complete

        stdout.write('\n')
        send_socket.close()
    # endregion

    # region Scanner
    def scan(self, network_interface, timeout=3, retry=3, target_ip_address=None, check_vendor=True,
             exclude_ip_address=None):

        # region Set variables
        self.target_ip_address = target_ip_address
        self.network_interface = network_interface
        self.timeout = int(timeout)
        self.retry_number = int(retry)
        # endregion

        # region Run sniffer
        tm = ThreadManager(2)
        tm.add_task(self.sniff)
        # endregion

        # region Run sender
        self.send()
        # endregion

        # region Create vendor list
        if check_vendor:
            self.vendor_list = self.base.get_mac_prefixes()
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

        # region Reset results and mac addresses list
        self.results = []
        self.mac_addresses = []
        # endregion

        # region Exclude IP address
        if exclude_ip_address is not None:
            self.results = self.unique_results
            self.unique_results = []
            for index in range(len(self.results)):
                if self.results[index]['ip-address'] != exclude_ip_address:
                    self.unique_results.append(self.results[index])
            self.results = []
        # endregion

        # region Get vendors
        for result_index in range(len(self.unique_results)):

            # Get current MAC address prefix
            current_mac_prefix = self.eth.get_mac_prefix(self.unique_results[result_index]['mac-address'])

            # Search this prefix in vendor list
            for vendor_index in range(len(self.vendor_list)):
                if current_mac_prefix == self.vendor_list[vendor_index]['prefix']:
                    self.unique_results[result_index]['vendor'] = self.vendor_list[vendor_index]['vendor']
                    break

            # Could not find this prefix in vendor list
            if 'vendor' not in self.unique_results[result_index].keys():
                self.unique_results[result_index]['vendor'] = "Unknown vendor"

        # endregion

        # region Return results
        return self.unique_results
        # endregion

    # endregion

    # region Get MAC address
    def get_mac_address(self, network_interface, target_ip_address, timeout=5, retry=5):
        try:

            # region Set variables
            self.target_ip_address = target_ip_address
            self.network_interface = network_interface
            self.timeout = int(timeout)
            self.retry_number = int(retry)
            # endregion

            # region Run sniffer
            tm = ThreadManager(2)
            tm.add_task(self.sniff)
            # endregion

            # region Run sender
            self.send()
            # endregion

            # region Wait
            sleep(self.timeout)
            # endregion

            # region Return
            if 'mac-address' in self.results[0].keys():
                return self.results[0]['mac-address']
            else:
                return "ff:ff:ff:ff:ff:ff"
            # endregion

        except IndexError:
            return "ff:ff:ff:ff:ff:ff"

        except KeyboardInterrupt:
            self.base.print_info("Exit")
            exit(0)

    # endregion

# endregion
