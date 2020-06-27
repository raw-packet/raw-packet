#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dhcpv6_fuzz.py: DHCPv6 fuzzing (dhcpv6_fuzz)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from argparse import ArgumentParser
from raw_packet.Scripts.Fuzz.remote import RemoteTest
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import RawSend, RawICMPv4
from typing import Union, List
from paramiko import RSAKey, SSHClient, AutoAddPolicy, ssh_exception
from pathlib import Path
from os.path import isfile
from dataclasses import dataclass
from re import compile
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
__script_name__ = 'DHCPv6 fuzzing (dhcpv6_fuzz)'
# endregion


# region Class DHCPv6Fuzz
class DHCPv6Fuzz:

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux'])
    _icmpv4: RawICMPv4 = RawICMPv4()
    _ssh_client: Union[None, SSHClient] = None
    _real_gateway_mac_address: Union[None, str] = None
    _windows_mac_address_regex = compile(r'([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})')

    _your: RemoteTest.Settings = RemoteTest.Settings()
    _target: RemoteTest.Settings = RemoteTest.Settings()
    _gateway: RemoteTest.Settings = RemoteTest.Settings()

    @dataclass
    class TestParameters:

        @dataclass
        class EthernetHeader:
            source_address: str = '12:34:56:78:90:ab'
            destination_address: str = '12:34:56:78:90:ac'
            type: int = 0x0806

        @dataclass
        class IPv6Header:
            source_address: str = '192.168.1.1'
            destination_address: str = '192.168.1.2'

        @dataclass
        class UDPHeader:
            source_port: int = 0
            destination_port: int = 0

        @dataclass
        class DHCPv6:
            test: int = 1
    
    _test_parameters: List[TestParameters] = list()
    # endregion

    # region Init
    def __init__(self,
                 network_interface: str,
                 number_of_packets_for_one_test: int = 5,
                 interval_between_packets_for_one_test: float = 0.2):

        self._number_of_packets: int = number_of_packets_for_one_test
        self._interval_between_packets: float = interval_between_packets_for_one_test

        _your = self._base.get_interface_settings(interface_name=network_interface,
                                                  required_parameters=['mac-address', 'ipv4-address'])
        self._your.network_interface = _your['network-interface']
        self._your.ipv4_address = _your['ipv4-address']
        self._your.mac_address = _your['mac-address']
        self._raw_send: RawSend = RawSend(network_interface=network_interface)
    # endregion

    # region Start spoofing
    def start(self,
              target_ip: str,
              target_mac: str,
              target_os: str,
              target_ssh_user: str,
              target_ssh_pass: Union[None, str],
              target_ssh_pkey: Union[None, str],
              gateway_ip: str,
              gateway_mac: str,
              all_tests: bool = False):

        # region Set variables
        self._target.ipv4_address = target_ip
        self._target.mac_address = target_mac
        self._target.os = target_os
        
        self._gateway.ipv4_address = gateway_ip
        self._gateway.mac_address = gateway_mac
        # endregion

        # region Connect to target over SSH
        _private_key: Union[None, RSAKey] = None
        self._ssh_client = SSHClient()
        self._ssh_client.set_missing_host_key_policy(AutoAddPolicy)

        if target_ssh_pass is None:
            _private_key_file: str = str(Path.home()) + '/.ssh/id_rsa'
            if target_ssh_pkey is not None:
                _private_key_file = target_ssh_pkey

            assert isfile(_private_key_file), \
                'Could not found file with private SSH key: ' + self._base.error_text(_private_key_file)

            try:
                _private_key = RSAKey.from_private_key_file(_private_key_file)
            except ssh_exception.SSHException:
                self._base.print_error('Paramiko exception: private SSH key from file: ',
                                       _private_key_file, ' is not a valid format. '
                                                          'Solution: https://github.com/paramiko/paramiko/issues/340#issuecomment-250429376')
                exit(2)

        try:
            if target_ssh_pass is not None:
                self._ssh_client.connect(hostname=self._target.ipv4_address,
                                         username=target_ssh_user,
                                         password=target_ssh_pass)
            if _private_key is not None:
                self._ssh_client.connect(hostname=self._target.ipv4_address,
                                         username=target_ssh_user,
                                         pkey=_private_key)

        except ssh_exception.AuthenticationException:
            self._base.print_error('SSH Authentication error to host: ',
                                   target_ssh_user + '@' + self._target.ipv4_address)
            exit(2)
        # endregion

        # region Source and destination addresses for L2 and L3 layers
        if all_tests:
            # Long list
            source_mac_addresses: List[str] = [
                self._your.mac_address,  # Your MAC address
                self._gateway.mac_address,  # Gateway MAC address
                self._target.mac_address,  # Target MAC address
                '00:00:00:00:00:00',  # Empty MAC address
                'ff:ff:ff:ff:ff:ff'  # Broadcast MAC address
            ]
            source_ip_addresses: List[str] = [
                self._your.ipv4_address,  # Your IP address
                self._gateway.ipv4_address,  # Gateway IP address
                self._target.ipv4_address,  # Target IP address
                '0.0.0.0',  # Empty IP address
                '255.255.255.255'  # Broadcast IP address
            ]
            destination_mac_addresses: List[str] = [
                self._your.mac_address,  # Your MAC address
                self._gateway.mac_address,  # Gateway MAC address
                self._target.mac_address,  # Target MAC address
                '00:00:00:00:00:00',  # Empty MAC address
                'ff:ff:ff:ff:ff:ff'  # Broadcast MAC address
            ]
            destination_ip_addresses: List[str] = [
                self._your.ipv4_address,  # Your IP address
                self._gateway.ipv4_address,  # Gateway IP address
                self._target.ipv4_address,  # Target IP address
                '0.0.0.0',  # Empty IP address
                '255.255.255.255'  # Broadcast IP address
            ]
        else:
            # Short list
            source_mac_addresses: List[str] = [
                self._your.mac_address,  # Your MAC address
            ]
            source_ip_addresses: List[str] = [
                self._gateway.ipv4_address,  # Gateway IP address
            ]
            destination_mac_addresses: List[str] = [
                self._target.mac_address,  # Target MAC address
                '00:00:00:00:00:00',  # Empty MAC address
                'ff:ff:ff:ff:ff:ff'  # Broadcast MAC address
            ]
            destination_ip_addresses: List[str] = [
                self._target.ipv4_address,  # Target IP address
                '0.0.0.0',  # Empty IP address
                '255.255.255.255'  # Broadcast IP address
            ]
        # endregion

        # region ICMPv4 types and codes
        # Types: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
        icmpv4_types: List[int] = [
            0,  # Echo Reply[RFC792]
            1,  # Unassigned
            2,  # Unassigned
            3,  # Destination Unreachable[RFC792]
            4,  # Source Quench(Deprecated)[RFC792][RFC6633]
            5,  # Redirect[RFC792]
            6,  # Alternate Host Address(Deprecated)[RFC6918]
            7,  # Unassigned
            8,  # Echo[RFC792]
            9,  # Router Advertisement[RFC1256]
            10,  # Router Solicitation[RFC1256]
            11,  # Time Exceeded[RFC792]
            12,  # Parameter Problem[RFC792]
            13,  # Timestamp[RFC792]
            14,  # Timestamp Reply[RFC792]
            15,  # Information Request(Deprecated)[RFC792][RFC6918]
            16,  # Information Reply(Deprecated)[RFC792][RFC6918]
            17,  # Address Mask Request(Deprecated)[RFC950][RFC6918]
            18,  # Address Mask Reply(Deprecated)[RFC950][RFC6918]
            19,  # Reserved(for Security)[Solo] - 20-29,  # Reserved ( for Robustness Experiment)[ZSu]
            30,  # Traceroute (Deprecated)[RFC1393][RFC6918]
            31,  # Datagram Conversion Error (Deprecated)[RFC1475][RFC6918]
            32,  # Mobile Host Redirect (Deprecated)[David_Johnson][RFC6918]
            33,  # IPv6 Where-Are-You (Deprecated)[Simpson][RFC6918]
            34,  # IPv6 I-Am-Here (Deprecated)[Simpson][RFC6918]
            35,  # Mobile Registration Request (Deprecated)[Simpson][RFC6918]
            36,  # Mobile Registration Reply (Deprecated)[Simpson][RFC6918]
            37,  # Domain Name Request (Deprecated)[RFC1788][RFC6918]
            38,  # Domain Name Reply (Deprecated)[RFC1788][RFC6918]
            39,  # SKIP (Deprecated)[Markson][RFC6918]
            40,  # Photuris[RFC2521]
            41,  # ICMP messages utilized by experimental mobility protocols such as Seamoby[RFC4065]
            42,  # Extended Echo Request[RFC8335]
            43,  # Extended Echo Reply[RFC8335] - 44-252,  # Unassigned
            253,  # RFC3692-style Experiment 1[RFC4727]
            254,  # RFC3692-style Experiment 2[RFC4727]
            255,  # Reserved[JBP]
        ]

        icmpv4_codes: List[int] = [
            0
        ]
        # endregion

        # region Network parameters permutations
        self._base.print_info('Destination MAC address: ', str(destination_mac_addresses))
        self._base.print_info('Source MAC address: ', str(source_mac_addresses))
        self._base.print_info('Destination IP address: ', str(destination_ip_addresses))
        self._base.print_info('Source IP address: ', str(source_ip_addresses))
        self._base.print_info('Make all permutations of tested parameters .....')

        for source_mac in source_mac_addresses:
            for destination_mac in destination_mac_addresses:
                for source_ip in source_ip_addresses:
                    for destination_ip in destination_ip_addresses:
                        for icmpv4_type in icmpv4_types:
                            for icmpv4_code in icmpv4_codes:

                                current_parameters = self.TestParameters()
                                current_parameters.EthernetHeader = self.TestParameters.EthernetHeader()
                                current_parameters.IPv4Header = self.TestParameters.IPv4Header()
                                current_parameters.ICMPv4 = self.TestParameters.ICMPv4()

                                current_parameters.EthernetHeader.source_address = source_mac
                                current_parameters.EthernetHeader.destination_address = destination_mac
                                current_parameters.IPv4Header.source_address = source_ip
                                current_parameters.IPv4Header.destination_address = destination_ip
                                current_parameters.ICMPv4.type = icmpv4_type
                                current_parameters.ICMPv4.code = icmpv4_code

                                self._test_parameters.append(current_parameters)

        self._base.print_info('All permutations are created, length of fuzzing packets: ',
                              str(len(self._test_parameters)))
        # endregion

        try:

            # region Check current Gateway MAC address
            remote_test: RemoteTest = RemoteTest(connected_ssh_client=self._ssh_client,
                                                 target=self._target, gateway=self._gateway,
                                                 test_parameters=self._test_parameters)
            current_gateway_mac_address = remote_test.get_ipv4_gateway_mac_address_over_ssh()
            assert current_gateway_mac_address is not None, \
                'Could not get gateway MAC address from host: ' + self._base.error_text(self._target.ipv4_address)
            if self._target.os == 'MacOS':
                self._real_gateway_mac_address = self._base.macos_encode_mac_address(self._gateway.mac_address)
            else:
                self._real_gateway_mac_address = self._gateway.mac_address
            assert current_gateway_mac_address == self._real_gateway_mac_address, \
                'Current gateway MAC address: ' + self._base.info_text(current_gateway_mac_address) + \
                ' on host: ' + self._base.error_text(self._target.ipv4_address) + \
                ' is not MAC address from arguments: ' + self._base.error_text(self._gateway.mac_address)
            self._base.print_info('Current Gateway MAC address: ', current_gateway_mac_address)
            # endregion

            # region Make and send packets
            for index in range(0, len(self._test_parameters)):

                packet: bytes = \
                    self._icmpv4.\
                        make_packet(ethernet_src_mac=self._test_parameters[index].EthernetHeader.source_address,
                                    ethernet_dst_mac=self._test_parameters[index].EthernetHeader.destination_address,
                                    ip_src=self._test_parameters[index].IPv4Header.source_address,
                                    ip_dst=self._test_parameters[index].IPv4Header.destination_address,
                                    icmp_type=self._test_parameters[index].ICMPv4.type,
                                    icmp_code=self._test_parameters[index].ICMPv4.code,
                                    data=b'1234567812345678123456781234567812345678123456781234567812345678')

                self._raw_send.send_packet(packet=packet, count=self._number_of_packets,
                                           delay=self._interval_between_packets)

                remote_test.check_ipv4_gateway_mac_address_over_ssh(test_parameters_index=index)
            # endregion

        except KeyboardInterrupt:
            self._base.print_info('Exit')
            exit(0)

        except AssertionError as Error:
            self._base.print_error(Error.args[0])
            exit(1)
    # endregion

# endregion


# region Main function
def main():
    
    # region Init Raw-packet classes
    base: Base = Base(admin_only=True, available_platforms=['Linux'])
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description='ICMPv4 fuzzing script')
    parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets', default=None)
    parser.add_argument('-T', '--target_ip', help='Set target IP address', required=True)
    parser.add_argument('-t', '--target_mac', help='Set target MAC address', required=True)
    parser.add_argument('-o', '--target_os', help='Set target OS (MacOS, Linux, Windows)', default='MacOS')
    parser.add_argument('-u', '--target_ssh_user', help='Set target user name for ssh', default='root')
    parser.add_argument('-p', '--target_ssh_pass', help='Set target password for ssh', default=None)
    parser.add_argument('-k', '--target_ssh_pkey', help='Set target private key for ssh', default=None)
    parser.add_argument('-G', '--gateway_ip', help='Set gateway IP address', required=True)
    parser.add_argument('-g', '--gateway_mac', help='Set gateway IP address', required=True)
    parser.add_argument('-A', '--all_tests', action='store_true', help='Test all fields')
    args = parser.parse_args()
    # endregion

    # region Print banner
    base.print_banner(__script_name__)
    # endregion

    try:
        # region Get current network interface
        current_network_interface: str = \
            base.network_interface_selection(interface_name=args.interface,
                                             message='Please select a network interface for ' +
                                                     __script_name__ + ' from table: ')
        # endregion

        # region Start ICMPv4 redirect (icmpv4_redirect)
        icmpv4_fuzz: ICMPv4Fuzz = ICMPv4Fuzz(network_interface=current_network_interface)
        icmpv4_fuzz.start(target_ip=args.target_ip,
                          target_mac=args.target_mac,
                          target_os=args.target_os,
                          target_ssh_user=args.target_ssh_user,
                          target_ssh_pass=args.target_ssh_pass,
                          target_ssh_pkey=args.target_ssh_pkey,
                          gateway_ip=args.gateway_ip,
                          gateway_mac=args.gateway_mac,
                          all_tests=args.all_tests)
        # endregion

    except KeyboardInterrupt:
        if not args.quiet:
            base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        if not args.quiet:
            base.print_error(Error.args[0])
        exit(1)
    # endregion

# endregion


# region Call main function
if __name__ == '__main__':
    main()
# endregion
