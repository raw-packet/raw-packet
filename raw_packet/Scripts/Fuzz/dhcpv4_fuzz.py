#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
dhcp_fuzz.py: DHCPv4 fuzzing (dhcp_fuzz)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Scripts.Fuzz.remote import RemoteTest
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import RawSend, RawSniff, RawEthernet, RawIPv4, RawUDP
from argparse import ArgumentParser
from struct import pack
from socket import inet_aton
from typing import Union, List, Dict
from dataclasses import dataclass
from itertools import product
from time import sleep
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
__script_name__ = 'DHCPv4 fuzzing (dhcp_fuzz)'
# endregion


# region Class DHCPv4Fuzz
class DHCPv4Fuzz:

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'MacOS', 'Windows'])
    _eth: RawEthernet = RawEthernet()
    _ipv4: RawIPv4 = RawIPv4()
    _udp: RawUDP = RawUDP()

    _remote_test: Union[None, RemoteTest] = None

    _your: RemoteTest.Settings = RemoteTest.Settings()
    _target: RemoteTest.Settings = RemoteTest.Settings()
    _gateway: RemoteTest.Settings = RemoteTest.Settings()

    @dataclass
    class TestParameters:

        @dataclass
        class EthernetHeader:
            source_address: str = '12:34:56:78:90:ab'
            destination_address: str = '12:34:56:78:90:ac'
            type: int = 0x0800

        @dataclass
        class IPv4Header:
            ttl: int = 64
            source_address: str = '192.168.0.1'
            destination_address: str = '192.168.0.2'
            protocol: int = 17

        @dataclass
        class UDPHeader:
            source_port: int = 68
            destination_port: int = 67
            test: int = 1

        @dataclass
        class BOOTPHeader:
            message_type: int = 1
            hardware_type: int = 1
            hardware_address_len: int = 6
            hops: int = 0
            transaction_id: int = 1
            seconds_elapsed: int = 0
            bootp_flags: int = 0
            client_ip: str = '0.0.0.0'
            your_ip: str = '0.0.0.0'
            next_server_ip: str = '0.0.0.0'
            relay_agent_ip: str = '0.0.0.0'
            client_mac: str = '12:34:56:78:90:ab'
            server_host_name: bytes = ''
            bootp_file_name: bytes = ''
            magic_cookie: bytes = b'\x63\x82\x53\x63'

        @dataclass
        class DHCPv4:
            options: List[bytes]
            padding: bytes = b''

    _test_parameters: List[TestParameters] = list()
    _test_parameters_index: int = 0
    _transactions: List[int] = list()
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

    # region Make DHCPv4 reply packet
    def make_reply(self,
                   bootp_transaction_id: int = 1,
                   dhcpv4_message_type: int = 2,
                   padding: int = 24) -> bytes:

        testing: Union[None, dataclass] = None
        try:
            testing: dataclass = self._test_parameters[self._test_parameters_index]
        except IndexError:
            self._base.print_info('All tests is done!')
            exit(0)

        bootp_packet: bytes = pack('!B', testing.BOOTPHeader.message_type)  # Message type
        bootp_packet += pack('!B', testing.BOOTPHeader.hardware_type)  # Hardware type: 1 - Ethernet
        bootp_packet += pack('!B', testing.BOOTPHeader.hardware_address_len)  # Hardware address length: 6 - Ethernet header length
        bootp_packet += pack('!B', testing.BOOTPHeader.hops)  # Number of hops
        bootp_packet += pack('!L', bootp_transaction_id)  # Transaction ID
        bootp_packet += pack('!H', testing.BOOTPHeader.seconds_elapsed)  # Seconds elapsed
        bootp_packet += pack('!H', testing.BOOTPHeader.bootp_flags)  # Flags
        bootp_packet += pack('!4s', inet_aton(testing.BOOTPHeader.client_ip))  # CIADDR - Client IP address
        bootp_packet += pack('!4s', inet_aton(testing.BOOTPHeader.your_ip))  # YIADDR - Your client IP address
        bootp_packet += pack('!4s', inet_aton(testing.BOOTPHeader.next_server_ip))  # SIADDR - Next server IP address
        bootp_packet += pack('!4s', inet_aton(testing.BOOTPHeader.relay_agent_ip))  # GIADDR - Relay agent IP address
        bootp_packet += self._eth.convert_mac(mac_address=testing.BOOTPHeader.client_mac)  # CHADDR - Client hardware address

        bootp_packet += b''.join(pack('B', 0) for _ in range(10))  # Client hardware address padding
        bootp_packet += testing.BOOTPHeader.server_host_name + b''.join(pack('B', 0) for _ in
                                                                  range(64 - len(testing.BOOTPHeader.server_host_name)))  # Server host name
        bootp_packet += testing.BOOTPHeader.bootp_file_name + b''.join(pack('B', 0) for _ in
                                                                 range(128 - len(testing.BOOTPHeader.bootp_file_name)))  # Boot file name
        bootp_packet += testing.BOOTPHeader.magic_cookie  # DHCPv4 magic cookie

        dhcpv4_packet: bytes = pack('!3B', 53, 1, dhcpv4_message_type)  # 53 DHCPv4 message type
        for option in testing.DHCPv4.options:
            dhcpv4_packet += option
        dhcpv4_packet += pack('B', 255)  # 255 - End of DHCPv4 options
        dhcpv4_packet += b''.join(pack('B', 0) for _ in range(padding))  # Add padding bytes in end of DHCPv4 packet

        eth_header: bytes = \
            self._eth.make_header(source_mac=testing.EthernetHeader.source_address,
                                  destination_mac=testing.EthernetHeader.destination_address,
                                  network_type=testing.EthernetHeader.type)

        ip_header: bytes = \
            self._ipv4.make_header(source_ip=testing.IPv4Header.source_address,
                                   destination_ip=testing.IPv4Header.destination_address,
                                   data_len=len(bootp_packet + dhcpv4_packet),
                                   transport_protocol_len=self._udp.header_length,
                                   transport_protocol_type=testing.IPv4Header.protocol,
                                   ttl=testing.IPv4Header.ttl)

        udp_header: bytes = \
            self._udp.make_header(source_port=testing.UDPHeader.source_port,
                                  destination_port=testing.UDPHeader.destination_port,
                                  data_length=len(bootp_packet + dhcpv4_packet))

        return eth_header + ip_header + udp_header + bootp_packet + dhcpv4_packet
    # endregion

    # region DHCPv4 reply
    def reply(self, packet: Dict):
        if 'DHCPv4' in packet.keys():

            # DHCPv4 Discover
            if packet['DHCPv4'][53] == 1:
                self._base.print_info('Index of tested parameters: ', str(self._test_parameters_index))
                if packet['BOOTP']['transaction-id'] not in self._transactions:
                    self._transactions.append(packet['BOOTP']['transaction-id'])
                else:
                    self._test_parameters_index += 1
                reply_packet = self.make_reply(bootp_transaction_id=packet['BOOTP']['transaction-id'],
                                               dhcpv4_message_type=2)
                self._raw_send.send_packet(reply_packet)
                self._base.print_info('DHCPv4 Discover from: ', packet['Ethernet']['source'])

            # DHCPv4 Request
            if packet['DHCPv4'][53] == 3:
                reply_packet = self.make_reply(bootp_transaction_id=packet['BOOTP']['transaction-id'],
                                               dhcpv4_message_type=5)
                self._raw_send.send_packet(reply_packet)
                self._base.print_info('DHCPv4 Request from: ', packet['Ethernet']['source'])
                sleep(2)
                current_gateway_ipv4_address = self._remote_test.get_ipv4_gateway_over_ssh()
                if current_gateway_ipv4_address is not None:
                    self._base.print_success('Index: ', str(self._test_parameters_index),
                                             ' Gateway: ', current_gateway_ipv4_address,
                                             ' Parameters: ', str(self._test_parameters[self._test_parameters_index]))
                else:
                    self._base.print_error('Index: ', str(self._test_parameters_index),
                                           ' Gateway: ', 'None',
                                           ' Parameters: ', str(self._test_parameters[self._test_parameters_index]))
                self._test_parameters_index += 1
                self._remote_test.dhcp_client_over_ssh()
    # endregion

    # region Start fuzzing
    def start(self,
              target_ip: str,
              target_new_ip: str,
              target_mac: str,
              target_os: str,
              target_iface: str,
              target_ssh_user: str,
              target_ssh_pass: Union[None, str],
              target_ssh_pkey: Union[None, str],
              gateway_ip: str,
              gateway_mac: str,
              all_tests: bool = False):

        # region Set variables
        self._target.ipv4_address = target_ip
        self._target.new_ipv4_address = target_new_ip
        self._target.mac_address = target_mac
        self._target.os = target_os
        self._target.network_interface = target_iface
        self._target.ssh_user = target_ssh_user
        self._target.ssh_password = target_ssh_pass
        self._target.ssh_private_key = target_ssh_pkey

        self._gateway.ipv4_address = gateway_ip
        self._gateway.mac_address = gateway_mac
        # endregion

        # region Source and destination addresses for Ethernet header
        if all_tests:
            # Long list
            ethernet_source_mac_addresses: List[str] = [
                self._your.mac_address,  # Your MAC address
                self._gateway.mac_address,  # Gateway MAC address
                self._target.mac_address,  # Target MAC address
                '00:00:00:00:00:00',  # Empty MAC address
                'ff:ff:ff:ff:ff:ff'  # Broadcast MAC address
            ]
            ethernet_destination_mac_addresses: List[str] = [
                self._your.mac_address,  # Your MAC address
                self._gateway.mac_address,  # Gateway MAC address
                self._target.mac_address,  # Target MAC address
                '00:00:00:00:00:00',  # Empty MAC address
                'ff:ff:ff:ff:ff:ff'  # Broadcast MAC address
            ]
        else:
            # Short list
            ethernet_source_mac_addresses: List[str] = [
                self._your.mac_address,  # Your MAC address
            ]
            ethernet_destination_mac_addresses: List[str] = [
                self._target.mac_address,  # Target MAC address
            ]
        # endregion

        # region Protocol type for Ethernet header
        if all_tests:
            # Long list
            ethernet_types: List[int] = [
                0x0000,  # IEEE802.3 Length Field [Neil_Sembower]
                0x0101,  # Experimental [Neil_Sembower]
                0x0200,  # XEROX PUP (see 0A00) Center, CSL-79-10, July 1979; also in IEEE Transactions on
                0x0201,  # PUP Addr Trans (see 0A01) [Neil_Sembower]
                0x0400,  # Nixdorf [Neil_Sembower]
                0x0600,  # XEROX NS IDP September 1980. And: "The Ethernet, A Local Area Network:
                0x0660,  # DLOG [Neil_Sembower]
                0x0661,  # DLOG [Neil_Sembower]
                0x0800,  # Internet Protocol version 4 [RFC7042]
                0x0801,  # X.75 Internet [Neil_Sembower]
                0x0802,  # NBS Internet [Neil_Sembower]
                0x0803,  # ECMA Internet [Neil_Sembower]
                0x0804,  # Chaosnet [Neil_Sembower]
                0x0805,  # X.25 Level 3 [Neil_Sembower]
                0x0806,  # Address Resolution Protocol [RFC7042]
                0x0807,  # XNS Compatability [Neil_Sembower]
                0x0808,  # Frame Relay ARP [RFC1701]
                0x081C,  # Symbolics Private [David_Plummer]
                0x0888,  # Xyplex [Neil_Sembower]
                0x0900,  # Ungermann-Bass net debugr [Neil_Sembower]
                0x0A00,  # Xerox IEEE802.3 PUP [Neil_Sembower]
                0x0A01,  # PUP Addr Trans [Neil_Sembower]
                0x0BAD,  # Banyan VINES [Neil_Sembower]
                0x0BAE,  # VINES Loopback [RFC1701]
                0x0BAF,  # VINES Echo [RFC1701]
                0x1000,  # Berkeley Trailer nego [Neil_Sembower]
                0x1001,  # Berkeley Trailer encap/IP [Neil_Sembower]
                0x1600,  # Valid Systems [Neil_Sembower]
                0x22F3,  # TRILL [RFC6325]
                0x22F4,  # L2-IS-IS [RFC6325]
                0x4242,  # PCS Basic Block Protocol [Neil_Sembower]
                0x5208,  # BBN Simnet [Neil_Sembower]
                0x6000,  # DEC Unassigned (Exp.) [Neil_Sembower]
                0x6001,  # DEC MOP Dump/Load [Neil_Sembower]
                0x6002,  # DEC MOP Remote Console [Neil_Sembower]
                0x6003,  # DEC DECNET Phase IV Route [Neil_Sembower]
                0x6004,  # DEC LAT [Neil_Sembower]
                0x6005,  # DEC Diagnostic Protocol [Neil_Sembower]
                0x6006,  # DEC Customer Protocol [Neil_Sembower]
                0x6007,  # DEC LAVC, SCA [Neil_Sembower]
                0x6008,  # DEC Unassigned [Neil_Sembower]
                0x6010,  # 3Com Corporation [Neil_Sembower]
                0x6558,  # Trans Ether Bridging [RFC1701]
                0x6559,  # Raw Frame Relay [RFC1701]
                0x7000,  # Ungermann-Bass download [Neil_Sembower]
                0x7002,  # Ungermann-Bass dia/loop [Neil_Sembower]
                0x7020,  # LRT [Neil_Sembower]
                0x7030,  # Proteon [Neil_Sembower]
                0x7034,  # Cabletron [Neil_Sembower]
                0x8003,  # Cronus VLN [RFC824][Daniel_Tappan]
                0x8004,  # Cronus Direct [RFC824][Daniel_Tappan]
                0x8005,  # HP Probe [Neil_Sembower]
                0x8006,  # Nestar [Neil_Sembower]
                0x8008,  # AT&T [Neil_Sembower]
                0x8010,  # Excelan [Neil_Sembower]
                0x8013,  # SGI diagnostics [Andrew_Cherenson]
                0x8014,  # SGI network games [Andrew_Cherenson]
                0x8015,  # SGI reserved [Andrew_Cherenson]
                0x8016,  # SGI bounce server [Andrew_Cherenson]
                0x8019,  # Apollo Domain [Neil_Sembower]
                0x802E,  # Tymshare [Neil_Sembower]
                0x802F,  # Tigan, Inc. [Neil_Sembower]
                0x8035,  # Reverse Address Resolution [RFC903][Joseph_Murdock]
                0x8036,  # Aeonic Systems [Neil_Sembower]
                0x8038,  # DEC LANBridge [Neil_Sembower]
                0x8039,  # DEC Unassigned [Neil_Sembower]
                0x803D,  # DEC Ethernet Encryption [Neil_Sembower]
                0x803E,  # DEC Unassigned [Neil_Sembower]
                0x803F,  # DEC LAN Traffic Monitor [Neil_Sembower]
                0x8040,  # DEC Unassigned [Neil_Sembower]
                0x8044,  # Planning Research Corp. [Neil_Sembower]
                0x8046,  # AT&T [Neil_Sembower]
                0x8047,  # AT&T [Neil_Sembower]
                0x8049,  # ExperData [Neil_Sembower]
                0x805B,  # Stanford V Kernel exp. [Neil_Sembower]
                0x805C,  # Stanford V Kernel prod. [Neil_Sembower]
                0x805D,  # Evans & Sutherland [Neil_Sembower]
                0x8060,  # Little Machines [Neil_Sembower]
                0x8062,  # Counterpoint Computers [Neil_Sembower]
                0x8065,  # Univ. of Mass. @ Amherst [Neil_Sembower]
                0x8066,  # Univ. of Mass. @ Amherst [Neil_Sembower]
                0x8067,  # Veeco Integrated Auto. [Neil_Sembower]
                0x8068,  # General Dynamics [Neil_Sembower]
                0x8069,  # AT&T [Neil_Sembower]
                0x806A,  # Autophon [Neil_Sembower]
                0x806C,  # ComDesign [Neil_Sembower]
                0x806D,  # Computgraphic Corp. [Neil_Sembower]
                0x806E,  # Landmark Graphics Corp. [Neil_Sembower]
                0x807A,  # Matra [Neil_Sembower]
                0x807B,  # Dansk Data Elektronik [Neil_Sembower]
                0x807C,  # Merit Internodal [Hans_Werner_Braun]
                0x807D,  # Vitalink Communications [Neil_Sembower]
                0x8080,  # Vitalink TransLAN III [Neil_Sembower]
                0x8081,  # Counterpoint Computers [Neil_Sembower]
                0x809B,  # Appletalk [Neil_Sembower]
                0x809C,  # Datability [Neil_Sembower]
                0x809F,  # Spider Systems Ltd. [Neil_Sembower]
                0x80A3,  # Nixdorf Computers [Neil_Sembower]
                0x80A4,  # Siemens Gammasonics Inc. [Neil_Sembower]
                0x80C0,  # DCA Data Exchange Cluster [Neil_Sembower]
                0x80C4,  # Banyan Systems [Neil_Sembower]
                0x80C5,  # Banyan Systems [Neil_Sembower]
                0x80C6,  # Pacer Software [Neil_Sembower]
                0x80C7,  # Applitek Corporation [Neil_Sembower]
                0x80C8,  # Intergraph Corporation [Neil_Sembower]
                0x80CD,  # Harris Corporation [Neil_Sembower]
                0x80CF,  # Taylor Instrument [Neil_Sembower]
                0x80D3,  # Rosemount Corporation [Neil_Sembower]
                0x80D5,  # IBM SNA Service on Ether [Neil_Sembower]
                0x80DD,  # Varian Associates [Neil_Sembower]
                0x80DE,  # Integrated Solutions TRFS [Neil_Sembower]
                0x80E0,  # Allen-Bradley [Neil_Sembower]
                0x80E4,  # Datability [Neil_Sembower]
                0x80F2,  # Retix [Neil_Sembower]
                0x80F3,  # AppleTalk AARP (Kinetics) [Neil_Sembower]
                0x80F4,  # Kinetics [Neil_Sembower]
                0x80F7,  # Apollo Computer [Neil_Sembower]
                0x80FF,  # Wellfleet Communications [Neil_Sembower]
                0x8100,  # formerly called the Q-Tag) [RFC7042]
                0x8101,  # Wellfleet Communications [Neil_Sembower]
                0x8107,  # Symbolics Private [Neil_Sembower]
                0x8130,  # Hayes Microcomputers [Neil_Sembower]
                0x8131,  # VG Laboratory Systems [Neil_Sembower]
                0x8132,  # Bridge Communications [Neil_Sembower]
                0x8137,  # Novell, Inc. [Neil_Sembower]
                0x8139,  # KTI [Neil_Sembower]
                0x8148,  # Logicraft [Neil_Sembower]
                0x8149,  # Network Computing Devices [Neil_Sembower]
                0x814A,  # Alpha Micro [Neil_Sembower]
                0x814C,  # SNMP [Joyce_K_Reynolds]
                0x814D,  # BIIN [Neil_Sembower]
                0x814E,  # BIIN [Neil_Sembower]
                0x814F,  # Technically Elite Concept [Neil_Sembower]
                0x8150,  # Rational Corp [Neil_Sembower]
                0x8151,  # Qualcomm [Neil_Sembower]
                0x815C,  # Computer Protocol Pty Ltd [Neil_Sembower]
                0x8164,  # Charles River Data System [Neil_Sembower]
                0x817D,  # XTP [Neil_Sembower]
                0x817E,  # SGI/Time Warner prop. [Neil_Sembower]
                0x8180,  # HIPPI-FP encapsulation [Neil_Sembower]
                0x8181,  # STP, HIPPI-ST [Neil_Sembower]
                0x8182,  # Reserved for HIPPI-6400 [Neil_Sembower]
                0x8183,  # Reserved for HIPPI-6400 [Neil_Sembower]
                0x8184,  # Silicon Graphics prop. [Neil_Sembower]
                0x818D,  # Motorola Computer [Neil_Sembower]
                0x819A,  # Qualcomm [Neil_Sembower]
                0x81A4,  # ARAI Bunkichi [Neil_Sembower]
                0x81A5,  # RAD Network Devices [Neil_Sembower]
                0x81B7,  # Xyplex [Neil_Sembower]
                0x81CC,  # Apricot Computers [Neil_Sembower]
                0x81D6,  # Artisoft [Neil_Sembower]
                0x81E6,  # Polygon [Neil_Sembower]
                0x81F0,  # Comsat Labs [Neil_Sembower]
                0x81F3,  # SAIC [Neil_Sembower]
                0x81F6,  # VG Analytical [Neil_Sembower]
                0x8203,  # Quantum Software [Neil_Sembower]
                0x8221,  # Ascom Banking Systems [Neil_Sembower]
                0x823E,  # Advanced Encryption Syste [Neil_Sembower]
                0x827F,  # Athena Programming [Neil_Sembower]
                0x8263,  # Charles River Data System [Neil_Sembower]
                0x829A,  # Inst Ind Info Tech [Neil_Sembower]
                0x829C,  # Taurus Controls [Neil_Sembower]
                0x82AC,  # Walker Richer & Quinn [Neil_Sembower]
                0x8694,  # Idea Courier [Neil_Sembower]
                0x869E,  # Computer Network Tech [Neil_Sembower]
                0x86A3,  # Gateway Communications [Neil_Sembower]
                0x86DB,  # SECTRA [Neil_Sembower]
                0x86DE,  # Delta Controls [Neil_Sembower]
                0x86DD,  # Internet Protocol version 6 [RFC7042]
                0x86DF,  # ATOMIC [Joe_Touch]
                0x86E0,  # Landis & Gyr Powers [Neil_Sembower]
                0x8700,  # Motorola [Neil_Sembower]
                0x876B,  # TCP/IP Compression [RFC1144][RFC1701]
                0x876C,  # IP Autonomous Systems [RFC1701]
                0x876D,  # Secure Data [RFC1701]
                0x8808,  # IEEE Std 802.3 - Ethernet [EPON][RFC7042]
                0x880B,  # Point-to-Point Protocol (PPP) [RFC7042]
                0x880C,  # General Switch Management [RFC7042]
                0x8847,  # MPLS [RFC5332]
                0x8848,  # MPLS with upstream-assigned [RFC5332]
                0x8861,  # Multicast Channel Allocation [RFC7042]
                0x8863,  # PPP over Ethernet (PPPoE) [RFC2516]
                0x8864,  # PPP over Ethernet (PPPoE) [RFC2516]
                0x888E,  # IEEE Std 802.1X - Port-based [IEEE]
                0x88A8,  # IEEE Std 802.1Q - Service VLAN [IEEE]
                0x8A96,  # Invisible Software [Neil_Sembower]
                0x88B5,  # IEEE Std 802 - Local [IEEE]
                0x88B6,  # IEEE Std 802 - Local [IEEE]
                0x88B7,  # IEEE Std 802 - OUI Extended [IEEE]
                0x88C7,  # IEEE Std 802.11 - [IEEE]
                0x88CC,  # IEEE Std 802.1AB - Link Layer [IEEE]
                0x88E5,  # IEEE Std 802.1AE - Media [IEEE]
                0x88E7,  # Provider Backbone Bridging [IEEE Std 802.1Q-2014]
                0x88F5,  # VLAN Registration Protocol [IEEE]
                0x88F6,  # Multicast Registration [IEEE]
                0x890D,  # IEEE Std 802.11 - Fast Roaming [IEEE]
                0x8917,  # IEEE Std 802.21 - Media [IEEE]
                0x8929,  # IEEE Std 802.1Qbe - Multiple [IEEE]
                0x893B,  # TRILL Fine Grained Labeling [RFC7172]
                0x8940,  # Protocol (also used in [IEEE]
                0x8946,  # TRILL RBridge Channel [RFC7178]
                0x8947,  # GeoNetworking as defined in [IEEE]
                0x894F,  # NSH (Network Service Header) [RFC8300]
                0x9000,  # Loopback [Neil_Sembower]
                0x9001,  # 3Com(Bridge) XNS Sys Mgmt [Neil_Sembower]
                0x9002,  # 3Com(Bridge) TCP-IP Sys [Neil_Sembower]
                0x9003,  # 3Com(Bridge) loop detect [Neil_Sembower]
                0x9A22,  # Multi-Topology [RFC8377]
                0xA0ED,  # LoWPAN encapsulation [RFC7973]
                0xB7EA,  # packets. When a GRE packet [RFC8157]
                0xFF00,  # BBN VITAL-LanBridge cache [Neil_Sembower]
                0xFF00,  # ISC Bunker Ramo [Neil_Sembower]
                0xFFFF,  # Reserved [RFC1701]
            ]
        else:
            # Short list
            ethernet_types: List[int] = [
                0x0800,  # IPv4
            ]
        # endregion

        # region IPv4 TTL
        if all_tests:
            # Long list
            ipv4_ttls: List[int] = [
                0, 1, 64, 255
            ]
        else:
            # Short list
            ipv4_ttls: List[int] = [
                255
            ]
        # endregion

        # region Source and destination addresses for IPv4 header
        if all_tests:
            # Long list
            ipv4_source_addresses: List[str] = [
                self._your.ipv4_address,  # Your IPv4 address
                self._gateway.ipv4_address,  # Gateway IPv4 address
                self._target.ipv4_address,  # Target IPv4 address
                self._target.new_ipv4_address,  # Target new IPv4 address
                '0.0.0.0',  # Empty IPv4 address
                '255.255.255.255'  # Broadcast IPv4 address
            ]
            ipv4_destination_addresses: List[str] = [
                self._your.ipv4_address,  # Your IPv4 address
                self._gateway.ipv4_address,  # Gateway IPv4 address
                self._target.ipv4_address,  # Target IPv4 address
                self._target.new_ipv4_address,  # Target new IPv4 address
                '0.0.0.0',  # Empty IPv4 address
                '255.255.255.255'  # Broadcast IPv4 address
            ]
        else:
            # Short list
            ipv4_source_addresses: List[str] = [
                self._your.ipv4_address,  # Your MAC address
            ]
            ipv4_destination_addresses: List[str] = [
                '255.255.255.255'  # Broadcast MAC address
            ]
        # endregion

        # region IPv4 Protocol
        if all_tests:
            # Long list
            ipv4_protocols: List[int] = [
                0x11,  # UDP protocol
            ]
        else:
            # Short list
            ipv4_protocols: List[int] = [
                0x11,  # UDP protocol
            ]
        # endregion

        # region Source and destination port for UDP header
        if all_tests:
            udp_source_ports: List[int] = [
                    67, 68
                ]
            udp_destination_ports: List[int] = [
                    67, 68
                ]
        else:
            udp_source_ports: List[int] = [
                67
            ]
            udp_destination_ports: List[int] = [
                68
            ]
        # endregion

        # region BOOTP message types
        if all_tests:
            # Long list
            bootp_message_types: List[int] = [
                0, 1, 2, 3
            ]
        else:
            # Short list
            bootp_message_types: List[int] = [
                2
            ]
        # endregion

        # region BOOTP hardware types
        if all_tests:
            # Long list
            bootp_hardware_types: List[int] = [
                0, 1, 2, 3
            ]
        else:
            # Short list
            bootp_hardware_types: List[int] = [
                1
            ]
        # endregion

        # region BOOTP hops
        if all_tests:
            # Long list
            bootp_hops: List[int] = [
                0, 1, 2, 3
            ]
        else:
            # Short list
            bootp_hops: List[int] = [
                0
            ]
        # endregion

        # region BOOTP seconds
        if all_tests:
            # Long list
            bootp_seconds: List[int] = [
                0, 1, 2, 3
            ]
        else:
            # Short list
            bootp_seconds: List[int] = [
                0
            ]
        # endregion

        # region BOOTP flags
        if all_tests:
            # Long list
            bootp_flags: List[int] = [
                0, 1, 2, 3
            ]
        else:
            # Short list
            bootp_flags: List[int] = [
                0
            ]
        # endregion

        # region BOOTP server names
        if all_tests:
            # Long list
            bootp_server_names: List[bytes] = [
                b'test',
                b''
            ]
        else:
            # Short list
            bootp_server_names: List[bytes] = [
                b''
            ]
        # endregion

        # region BOOTP boot names
        if all_tests:
            # Long list
            bootp_boot_names: List[bytes] = [
                b'test',
                b''
            ]
        else:
            # Short list
            bootp_boot_names: List[bytes] = [
                b''
            ]
        # endregion

        # region BOOTP magic cookies
        if all_tests:
            # Long list
            bootp_magic_cookies: List[bytes] = [
                b'\x63\x82\x53\x63',
                b'\x64\x82\x53\x64',
                b'\x00\x00\x00\x00'
            ]
        else:
            # Short list
            bootp_magic_cookies: List[bytes] = [
                b'\x63\x82\x53\x63',
            ]
        # endregion

        # region BOOTP client mac addresses
        if all_tests:
            # Long list
            bootp_client_macs: List[str] = [
                self._target.mac_address,  # Target MAC address
                '00:00:00:00:00:00',  # Empty MAC address
                'ff:ff:ff:ff:ff:ff',  # Broadcast MAC address
            ]
        else:
            # Short list
            bootp_client_macs: List[str] = [
                self._target.mac_address,  # Target MAC address
            ]
        # endregion

        # region BOOTP client IP addresses
        if all_tests:
            # Long list
            bootp_client_ips: List[str] = [
                self._your.ipv4_address,  # Your IPv4 address
                self._gateway.ipv4_address,  # Gateway IPv4 address
                self._target.ipv4_address,  # Target IPv4 address
                self._target.new_ipv4_address,  # Target new IPv4 address
                '0.0.0.0',  # Empty IPv4 address
                '255.255.255.255'  # Broadcast IPv4 address
            ]
        else:
            # Short list
            bootp_client_ips: List[str] = [
                '0.0.0.0',  # Empty IPv4 address
            ]
        # endregion

        # region DHCPv4 options
        if all_tests:
            # Long list
            dhcpv4_options: Dict[int, List[bytes]] = {
                1: [inet_aton('255.255.255.0')],  # Subnet Mask
                3: [inet_aton(self._your.ipv4_address)],  # Router address
                6: [inet_aton(self._your.ipv4_address)],  # DNS server address
                15: [b'test'],  # DNS server address
                51: [b'\xff\xff\xff\xff'],  # Lease time
                54: [inet_aton(self._your.ipv4_address)],  # DHCP server identifier
                119: [b'fsdfdsafrewqfsadfdsag']  # Domain Search
            }
        else:
            # Short list
            dhcpv4_options: Dict[int, List[bytes]] = {
                1: [inet_aton('255.255.255.0'),
                    inet_aton('255.255.0.0')],  # Subnet Mask
                3: [inet_aton(self._your.ipv4_address)],  # Router address
                6: [inet_aton(self._your.ipv4_address)],  # DNS server address
                15: [b'test'],  # DNS server address
                51: [b'\xff\xff\xff\xff'],  # Lease time
                54: [inet_aton(self._your.ipv4_address)],  # DHCP server identifier
                }

        dhcpv4_options_list: List[Dict[int, bytes]] = \
            [dict(zip(dhcpv4_options, value)) for value in product(*dhcpv4_options.values())]
        # endregion

        # region Print test parameters
        self._base.print_info('Ethernet source MAC addresses: ', str(ethernet_source_mac_addresses))
        self._base.print_info('Ethernet destination MAC addresses: ', str(ethernet_destination_mac_addresses))
        self._base.print_info('Ethernet protocol types: ', str(ethernet_types))

        self._base.print_info('IPv4 TTLs: ', str(ipv4_ttls))
        self._base.print_info('IPv4 source addresses: ', str(ipv4_source_addresses))
        self._base.print_info('IPv4 destination addresses: ', str(ipv4_destination_addresses))
        self._base.print_info('IPv4 Protocols: ', str(ipv4_protocols))

        self._base.print_info('UDP source ports: ', str(udp_source_ports))
        self._base.print_info('UDP destination ports: ', str(udp_destination_ports))

        self._base.print_info('BOOTP message types: ', str(bootp_message_types))
        self._base.print_info('BOOTP hardware types: ', str(bootp_hardware_types))
        self._base.print_info('BOOTP hops: ', str(bootp_hops))
        self._base.print_info('BOOTP seconds: ', str(bootp_seconds))
        self._base.print_info('BOOTP flags: ', str(bootp_flags))
        self._base.print_info('BOOTP client IPv4 addresses: ', str(bootp_client_ips))
        self._base.print_info('BOOTP client mac addresses: ', str(bootp_client_macs))
        self._base.print_info('BOOTP server host names: ', str(bootp_server_names))
        self._base.print_info('BOOTP boot file names: ', str(bootp_boot_names))
        self._base.print_info('BOOTP magic cookies: ', str(bootp_magic_cookies))

        self._base.print_info('DHCPv4 options: ', str(dhcpv4_options_list))
        # endregion

        # region Network parameters permutations
        self._base.print_info('Make all permutations of tested parameters .....')

        eth_params: List[dataclass] = list()
        ipv4_params: List[dataclass] = list()
        udp_params: List[dataclass] = list()
        bootp_params: List[dataclass] = list()

        # region Ethernet
        for eth_src_mac in ethernet_source_mac_addresses:
            for eth_dst_mac in ethernet_destination_mac_addresses:
                for eth_type in ethernet_types:
                    params = self.TestParameters()
                    params.EthernetHeader = self.TestParameters.EthernetHeader()

                    params.EthernetHeader.source_address = eth_src_mac
                    params.EthernetHeader.destination_address = eth_dst_mac
                    params.EthernetHeader.type = eth_type

                    eth_params.append(params)
        # endregion

        # region IPv4
        for eth in eth_params:
            for ipv4_ttl in ipv4_ttls:
                for ipv4_src in ipv4_source_addresses:
                    for ipv4_dst in ipv4_destination_addresses:
                        for ipv4_protocol in ipv4_protocols:
                            params = self.TestParameters()
                            params.EthernetHeader = self.TestParameters.EthernetHeader()
                            params.IPv4Header = self.TestParameters.IPv4Header()

                            params.EthernetHeader.source_address = eth.EthernetHeader.source_address
                            params.EthernetHeader.destination_address = eth.EthernetHeader.destination_address
                            params.EthernetHeader.type = eth.EthernetHeader.type

                            params.IPv4Header.ttl = ipv4_ttl
                            params.IPv4Header.source_address = ipv4_src
                            params.IPv4Header.destination_address = ipv4_dst
                            params.IPv4Header.protocol = ipv4_protocol

                            ipv4_params.append(params)
        # endregion

        # region UDP
        for eth in eth_params:
            for ipv4 in ipv4_params:
                for src_port in udp_source_ports:
                    for dst_port in udp_destination_ports:
                        params = self.TestParameters()
                        params.EthernetHeader = self.TestParameters.EthernetHeader()
                        params.IPv4Header = self.TestParameters.IPv4Header()
                        params.UDPHeader = self.TestParameters.UDPHeader()

                        params.EthernetHeader.source_address = eth.EthernetHeader.source_address
                        params.EthernetHeader.destination_address = eth.EthernetHeader.destination_address
                        params.EthernetHeader.type = eth.EthernetHeader.type

                        params.IPv4Header.ttl = ipv4.IPv4Header.ttl
                        params.IPv4Header.source_address = ipv4.IPv4Header.source_address
                        params.IPv4Header.destination_address = ipv4.IPv4Header.destination_address
                        params.IPv4Header.protocol = ipv4.IPv4Header.protocol

                        params.UDPHeader.source_port = src_port
                        params.UDPHeader.destination_port = dst_port

                        udp_params.append(params)
        # endregion

        # region BOOTP
        for eth in eth_params:
            for ipv4 in ipv4_params:
                for udp in udp_params:
                    for bootp_message_type in bootp_message_types:
                        for bootp_hardware_type in bootp_hardware_types:
                            for bootp_hop in bootp_hops:
                                for bootp_second in bootp_seconds:
                                    for bootp_flag in bootp_flags:
                                        for bootp_client_ip in bootp_client_ips:
                                            for bootp_client_mac in bootp_client_macs:
                                                for bootp_server_name in bootp_server_names:
                                                    for bootp_boot_name in bootp_boot_names:
                                                        for bootp_magic_cookie in bootp_magic_cookies:

                                                            params = self.TestParameters()
                                                            params.EthernetHeader = \
                                                                self.TestParameters.EthernetHeader()
                                                            params.IPv4Header = \
                                                                self.TestParameters.IPv4Header()
                                                            params.UDPHeader = \
                                                                self.TestParameters.UDPHeader()
                                                            params.BOOTPHeader = \
                                                                self.TestParameters.BOOTPHeader()

                                                            params.EthernetHeader.source_address = \
                                                                eth.EthernetHeader.source_address
                                                            params.EthernetHeader.destination_address = \
                                                                eth.EthernetHeader.destination_address
                                                            params.EthernetHeader.type = \
                                                                eth.EthernetHeader.type

                                                            params.IPv4Header.ttl = \
                                                                ipv4.IPv4Header.ttl
                                                            params.IPv4Header.source_address = \
                                                                ipv4.IPv4Header.source_address
                                                            params.IPv4Header.destination_address = \
                                                                ipv4.IPv4Header.destination_address
                                                            params.IPv4Header.protocol = \
                                                                ipv4.IPv4Header.protocol

                                                            params.UDPHeader.source_port = \
                                                                udp.UDPHeader.source_port
                                                            params.UDPHeader.destination_port = \
                                                                udp.UDPHeader.destination_port

                                                            params.BOOTPHeader.message_type = \
                                                                bootp_message_type
                                                            params.BOOTPHeader.hardware_type = \
                                                                bootp_hardware_type
                                                            params.BOOTPHeader.hops = \
                                                                bootp_hop
                                                            params.BOOTPHeader.seconds_elapsed = \
                                                                bootp_second
                                                            params.BOOTPHeader.bootp_flags = \
                                                                bootp_flag
                                                            params.BOOTPHeader.client_ip = \
                                                                bootp_client_ip
                                                            params.BOOTPHeader.client_mac = \
                                                                bootp_client_mac
                                                            params.BOOTPHeader.server_host_name = \
                                                                bootp_server_name
                                                            params.BOOTPHeader.bootp_file_name = \
                                                                bootp_boot_name
                                                            params.BOOTPHeader.magic_cookie = \
                                                                bootp_magic_cookie

                                                            bootp_params.append(params)
        # endregion

        # region DHCPv4
        for eth in eth_params:
            for ipv4 in ipv4_params:
                for udp in udp_params:
                    for bootp in bootp_params:
                        for dhcpv4_options in dhcpv4_options_list:

                            dhcpv4_options_bytes: List[bytes] = list()
                            for key, value in dhcpv4_options.items():
                                dhcpv4_options_bytes.append(pack('!2B', key, len(value)) + value)

                            params = self.TestParameters()
                            params.EthernetHeader = \
                                self.TestParameters.EthernetHeader()
                            params.IPv4Header = \
                                self.TestParameters.IPv4Header()
                            params.UDPHeader = \
                                self.TestParameters.UDPHeader()
                            params.BOOTPHeader = \
                                self.TestParameters.BOOTPHeader()
                            params.DHCPv4 = \
                                self.TestParameters.DHCPv4(options=dhcpv4_options_bytes)

                            params.EthernetHeader.source_address = \
                                eth.EthernetHeader.source_address
                            params.EthernetHeader.destination_address = \
                                eth.EthernetHeader.destination_address
                            params.EthernetHeader.type = \
                                eth.EthernetHeader.type

                            params.IPv4Header.ttl = \
                                ipv4.IPv4Header.ttl
                            params.IPv4Header.source_address = \
                                ipv4.IPv4Header.source_address
                            params.IPv4Header.destination_address = \
                                ipv4.IPv4Header.destination_address
                            params.IPv4Header.protocol = \
                                ipv4.IPv4Header.protocol

                            params.UDPHeader.source_port = \
                                udp.UDPHeader.source_port
                            params.UDPHeader.destination_port = \
                                udp.UDPHeader.destination_port

                            params.BOOTPHeader.message_type = \
                                bootp.BOOTPHeader.message_type
                            params.BOOTPHeader.hardware_type = \
                                bootp.BOOTPHeader.hardware_type
                            params.BOOTPHeader.hops = \
                                bootp.BOOTPHeader.hops
                            params.BOOTPHeader.seconds_elapsed = \
                                bootp.BOOTPHeader.seconds_elapsed
                            params.BOOTPHeader.bootp_flags = \
                                bootp.BOOTPHeader.bootp_flags
                            params.BOOTPHeader.client_ip = \
                                bootp.BOOTPHeader.client_ip
                            params.BOOTPHeader.client_mac = \
                                bootp.BOOTPHeader.client_mac
                            params.BOOTPHeader.server_host_name = \
                                bootp.BOOTPHeader.server_host_name
                            params.BOOTPHeader.bootp_file_name = \
                                bootp.BOOTPHeader.bootp_file_name
                            params.BOOTPHeader.magic_cookie = \
                                bootp.BOOTPHeader.magic_cookie

                            self._test_parameters.append(params)
        # endregion

        self._base.print_info('All permutations are created, length of fuzzing packets: ',
                              str(len(self._test_parameters)))
        # endregion

        try:

            # region Check current Gateway MAC address
            self._remote_test: RemoteTest = RemoteTest(target=self._target, gateway=self._gateway,
                                                       test_parameters=self._test_parameters)
            current_gateway_ipv4_address = self._remote_test.get_ipv4_gateway_over_ssh()
            # assert current_gateway_ipv4_address is not None, \
            #     'Could not get gateway IPv4 address from host: ' + self._base.error_text(self._target.ipv4_address)
            # assert current_gateway_ipv4_address == self._gateway.ipv4_address, \
            #     'Current gateway IPv4 address: ' + self._base.info_text(current_gateway_ipv4_address) + \
            #     ' on host: ' + self._base.error_text(self._target.ipv4_address) + \
            #     ' is not IPv4 address from arguments: ' + self._base.error_text(self._gateway.ipv4_address)
            self._base.print_info('Current Gateway IPv4 address: ', str(current_gateway_ipv4_address))
            # endregion

            # region Start sniffing DHCPv4 requests from target host
            raw_sniff: RawSniff = RawSniff()
            network_filters = {
                'Ethernet': {'source': self._target.mac_address, 'destination': 'ff:ff:ff:ff:ff:ff'},
                # 'IPv4': {'source-ip': '0.0.0.0', 'destination-ip': '255.255.255.255'},
                'UDP': {'source-port': 68, 'destination-port': 67},
            }
            self._remote_test.dhcp_client_over_ssh()
            raw_sniff.start(protocols=['IPv4', 'UDP', 'DHCPv4'], prn=self.reply, filters=network_filters,
                            network_interface=self._your.network_interface)
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
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'MacOS', 'Windows'])
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description='ICMPv4 fuzzing script')
    parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets', default=None)
    parser.add_argument('-T', '--target_ip', help='Set target IP address', required=True)
    parser.add_argument('-N', '--target_new_ip', help='Set target new IP address', required=True)
    parser.add_argument('-t', '--target_mac', help='Set target MAC address', required=True)
    parser.add_argument('-o', '--target_os', help='Set target OS (MacOS, Linux, Windows)', default='MacOS')
    parser.add_argument('-I', '--target_iface', help='Set target Network interface', default='en0')
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
        dhcpv4_fuzz: DHCPv4Fuzz = DHCPv4Fuzz(network_interface=current_network_interface)
        dhcpv4_fuzz.start(target_ip=args.target_ip,
                          target_mac=args.target_mac,
                          target_os=args.target_os,
                          target_iface=args.target_iface,
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


# tested_index: int = 0
# transactions: List[int] = list()
# send_transactions: Dict[int, List[int]] = {}
#
#
#
#
#
# # region Main function
# if __name__ == '__main__':
#
#     # region Import Raw-packet classes
#     path.append(dirname(dirname(dirname(abspath(__file__)))))
#
#     from raw_packet.Utils.base import Base
#     from raw_packet.Utils.network import RawEthernet, RawIPv4, RawUDP, RawDHCPv4, RawSniff
#     from raw_packet.Utils.tm import ThreadManager
#
#     base: Base = Base()
#     eth: RawEthernet = RawEthernet()
#     ipv4: RawIPv4 = RawIPv4()
#     udp: RawUDP = RawUDP()
#     sniff: RawSniff = RawSniff()
#     dhcpv4: RawDHCPv4 = RawDHCPv4()
#     thread_manager: ThreadManager = ThreadManager(2)
#     # endregion
#
#     # region Raw socket
#     raw_socket: socket = socket(AF_PACKET, SOCK_RAW)
#     # endregion
#
#     # region Check user and platform
#     base.check_user()
#     base.check_platform()
#     # endregion
#
#     # region Parse script arguments
#     parser: ArgumentParser = ArgumentParser(description='DHCPv4 fuzzing script')
#     parser.add_argument('-i', '--interface', help='Set interface name for send ARP packets', default=None)
#     parser.add_argument('-m', '--target_mac', help='Set target MAC address', required=True)
#     parser.add_argument('-t', '--target_ip', help='Set target IPv4 address', required=True)
#     parser.add_argument('-o', '--target_os', help='Set target OS (MacOS, Linux, Windows)', default='MacOS')
#     parser.add_argument('-e', '--target_interface', help='Set target OS network interface', default='en0')
#     parser.add_argument('-u', '--target_ssh_user', help='Set target user name for ssh', default='root')
#     parser.add_argument('-p', '--target_ssh_pass', help='Set target password for ssh', default=None)
#     parser.add_argument('-k', '--target_ssh_pkey', help='Set target private key for ssh', default=None)
#     parser.add_argument('-g', '--gateway_ip', help='Set gateway IP address', required=True)
#     parser.add_argument('-s', '--send', action='store_true', help='Send packets to target')
#     parser.add_argument('-A', '--all_tests', action='store_true', help='Test all fields')
#     parser.add_argument('-B', '--only_broadcast', action='store_true', help='Send only Broadcast packets')
#     parser.add_argument('-M', '--only_multicast', action='store_true', help='Send only Multicast packets')
#     args = parser.parse_args()
#     # endregion
#
#     # region Get listen network interface, your IP and MAC address, first and last IP in local network
#     if args.interface is None:
#         base.print_warning('Please set a network interface for send ARP spoofing packets ...')
#     current_network_interface: str = base.network_interface_selection(args.interface)
#     your_mac_address: str = base.get_interface_mac_address(current_network_interface)
#     your_ip_address: str = base.get_interface_ip_address(current_network_interface)
#     first_ip_address: str = base.get_first_ip_on_interface(current_network_interface)
#     last_ip_address: str = base.get_last_ip_on_interface(current_network_interface)
#     # endregion
#
#     try:
#         # region Bind raw socket
#         raw_socket.bind((current_network_interface, 0))
#         # endregion
#
#         # region SSH and current gateway address
#         private_key: Union[None, RSAKey] = None
#
#         if args.target_ssh_pkey is None and args.target_ssh_pass is None:
#             default_private_key_file: str = str(Path.home()) + '/.ssh/id_rsa'
#             assert isfile(default_private_key_file), \
#                 'Could not found private SSH key: ' + base.error_text(default_private_key_file)
#             private_key = RSAKey.from_private_key_file(default_private_key_file)
#
#         if args.target_ssh_pkey is not None:
#             private_key = RSAKey.from_private_key_file(args.target_ssh_pkey)
#
#         assert private_key is not None or args.target_ssh_pass is not None, \
#             'Password and private key file for SSH is None!' + \
#             ' Please set SSH password: ' + base.info_text('--target_ssh_pass <ssh_password>') + \
#             ' or SSH private key file: ' + base.info_text('--target_ssh_pkey <ssh_pkey_path>')
#         # endregion
#
#         # region Variables
#         number_of_arp_packets: int = 5
#         interval_between_sending_packets: float = 0.2
#
#         tested_parameters: List[Dict[str, Dict[str, Union[int, str]]]] = list()
#
#         link_layer_fields: List[Dict[str, Union[int, str]]] = list()
#         network_layer_fields: List[Dict[str, Union[int, str]]] = list()
#         transport_layer_fields: List[Dict[str, Union[int, str]]] = list()
#         bootp_fields: List[Dict[str, Union[int, str]]] = list()
#         dhcp_options: List[Dict[str, Union[int, str]]] = list()
#         # endregion
#
#         # region Make tested parameters
#
#         # region Link layer
#         base.print_info('Make link layer tested parameters ...')
#         if args.all_tests:
#             # Long list
#             destination_mac_addresses: List[str] = [
#                 args.target_mac,  # Target MAC address
#                 'ff:ff:ff:ff:ff:ff',  # Broadcast MAC address
#                 '33:33:00:00:00:01',  # IPv6 multicast MAC address
#                 '01:00:5e:00:00:01',  # IPv4 multicast MAC address
#             ]
#         elif args.only_broadcast:
#             # Only Broadcast packets
#             destination_mac_addresses: List[str] = [
#                 'ff:ff:ff:ff:ff:ff',  # Broadcast MAC address
#             ]
#         elif args.only_multicast:
#             # Only Multicast packets
#             destination_mac_addresses: List[str] = [
#                 '33:33:00:00:00:01',  # IPv6 multicast MAC address
#                 '01:00:5e:00:00:01',  # IPv4 multicast MAC address
#             ]
#         else:
#             # Short list
#             destination_mac_addresses: List[str] = [
#                 args.target_mac,  # Target MAC address
#                 'ff:ff:ff:ff:ff:ff',  # Broadcast MAC address
#             ]
#         source_mac_addresses: List[str] = [
#             your_mac_address  # Your MAC address
#         ]
#         network_types: List[int] = [
#             ipv4.header_type  # IPv4 protocol
#         ]
#         for destination_mac_address in destination_mac_addresses:
#             for source_mac_address in source_mac_addresses:
#                 for network_type in network_types:
#                     link_layer_fields.append({
#                         'destination_mac_address': destination_mac_address,
#                         'source_mac_address': source_mac_address,
#                         'network_type': network_type
#                     })
#         base.print_info('Destination MAC address: ', str(destination_mac_addresses))
#         base.print_info('Source MAC address: ', str(source_mac_addresses))
#         base.print_info('Network type: ', str(network_types))
#         # endregion
#
#         # region Network layer
#         base.print_info('Make network layer tested parameters ...')
#         if args.all_tests:
#             # Long list
#             destination_ip_addresses: List[str] = [
#                 args.target_ip,  # Target IPv4 address
#                 '255.255.255.255',  # Broadcast IPv4 address
#                 '224.0.0.1',  # IPv4 multicast IPv4 address
#                 '0.0.0.0',  # Zeros
#             ]
#             source_ip_addresses: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#                 '255.255.255.255',  # Broadcast IPv4 address
#                 '224.0.0.1',  # IPv4 multicast IPv4 address
#                 '0.0.0.0',  # Zeros
#             ]
#         elif args.only_broadcast:
#             # Only Broadcast packets
#             destination_ip_addresses: List[str] = [
#                 '255.255.255.255',  # Broadcast IPv4 address
#             ]
#             source_ip_addresses: List[str] = [
#                 '255.255.255.255',  # Broadcast IPv4 address
#             ]
#         elif args.only_multicast:
#             # Only Multicast packets
#             destination_ip_addresses: List[str] = [
#                 '224.0.0.1',  # IPv4 multicast IPv4 address
#             ]
#             source_ip_addresses: List[str] = [
#                 '224.0.0.1',  # IPv4 multicast IPv4 address
#             ]
#         else:
#             # Short list
#             destination_ip_addresses: List[str] = [
#                 args.target_ip,  # Target IPv4 address
#                 '0.0.0.0',  # Zeros
#                 '255.255.255.255',  # Broadcast IPv4 address
#             ]
#             source_ip_addresses: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#                 '0.0.0.0',  # Zeros
#                 '255.255.255.255',  # Broadcast IPv4 address
#             ]
#         transport_types: List[int] = [
#             udp.header_type
#         ]
#         for destination_ip_address in destination_ip_addresses:
#             for source_ip_address in source_ip_addresses:
#                 for transport_type in transport_types:
#                     network_layer_fields.append({
#                         'destination_ip_address': destination_ip_address,
#                         'source_ip_address': source_ip_address,
#                         'transport_type': transport_type
#                     })
#         base.print_info('Destination IP address: ', str(destination_ip_addresses))
#         base.print_info('Source IP address: ', str(source_ip_addresses))
#         base.print_info('Transport type: ', str(transport_types))
#         # endregion
#
#         # region Transport layer
#         base.print_info('Make transport layer tested parameters ...')
#         if args.all_tests:
#             # Long list
#             destination_ports: List[int] = [
#                 67,  # DHCPv4 response source port
#                 68,  # DHCPv4 response destination port
#             ]
#             source_ports: List[int] = [
#                 68,  # DHCPv4 response destination port
#                 67,  # DHCPv4 response source port
#                 546,  # DHCPv6 response destination port
#                 547,  # DHCPv6 response source port
#             ]
#         else:
#             # Short list
#             destination_ports: List[int] = [
#                 67,  # DHCPv4 response source port
#                 68,  # DHCPv4 response destination port
#             ]
#             source_ports: List[int] = [
#                 67,  # DHCPv4 response source port
#                 68,  # DHCPv4 response destination port
#             ]
#         for destination_port in destination_ports:
#             for source_port in source_ports:
#                 transport_layer_fields.append({
#                     'destination_port': destination_port,
#                     'source_port': source_port
#                 })
#         base.print_info('Destination port: ', str(destination_ports))
#         base.print_info('Source port: ', str(source_ports))
#         # endregion
#
#         # region BOOTP
#         base.print_info('Make BOOTP tested parameters ...')
#         if args.all_tests:
#             # Long list
#             bootp_message_types: List[int] = [
#                 1,  # BOOTP Request
#                 2,  # BOOTP Reply
#                 3,  # BOOTP Unknown message type
#             ]
#             bootp_hardware_types: List[int] = [
#                 1,  # Ethernet
#             ]
#             bootp_hardware_lengths: List[int] = [
#                 6,  # Ethernet hardware address length
#             ]
#             bootp_hops: List[int] = [
#                 0,
#                 254
#             ]
#             bootp_flags: List[int] = [
#                 0,
#                 65535,
#             ]
#             bootp_client_ips: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#                 args.target_ip,  # Target IPv4 address
#                 '255.255.255.255',  # Broadcast IPv4 address
#                 '224.0.0.1',  # IPv4 multicast IPv4 address
#                 '0.0.0.0',  # Zeros
#             ]
#             bootp_your_ips: List[str] = [
#                 args.target_ip,  # Target IPv4 address
#                 '255.255.255.255',  # Broadcast IPv4 address
#                 '224.0.0.1',  # IPv4 multicast IPv4 address
#                 '0.0.0.0',  # Zeros
#             ]
#             bootp_next_server_ips: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#                 '255.255.255.255',  # Broadcast IPv4 address
#                 '224.0.0.1',  # IPv4 multicast IPv4 address
#                 '0.0.0.0',  # Zeros
#             ]
#             bootp_relay_agent_ips: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#                 '255.255.255.255',  # Broadcast IPv4 address
#                 '224.0.0.1',  # IPv4 multicast IPv4 address
#                 '0.0.0.0',  # Zeros
#             ]
#             bootp_client_macs: List[str] = [
#                 args.target_mac,  # Target MAC address
#                 your_mac_address,  # Your MAC address
#                 'ff:ff:ff:ff:ff:ff',  # Broadcast MAC address
#                 '33:33:00:00:00:01',  # IPv6 multicast MAC address
#                 '01:00:5e:00:00:01',  # IPv4 multicast MAC address
#             ]
#         else:
#             # Short list
#             bootp_message_types: List[int] = [
#                 1,  # BOOTP Request
#                 2,  # BOOTP Reply
#                 3,  # BOOTP Unknown message type
#             ]
#             bootp_hardware_types: List[int] = [
#                 1,  # Ethernet
#             ]
#             bootp_hardware_lengths: List[int] = [
#                 6,  # Ethernet hardware address length
#             ]
#             bootp_hops: List[int] = [
#                 0,
#             ]
#             bootp_flags: List[int] = [
#                 0,
#             ]
#             bootp_client_ips: List[str] = [
#                 '0.0.0.0',  # Zeros
#             ]
#             bootp_your_ips: List[str] = [
#                 args.target_ip,  # Target IPv4 address
#             ]
#             bootp_next_server_ips: List[str] = [
#                 '0.0.0.0',  # Zeros
#             ]
#             bootp_relay_agent_ips: List[str] = [
#                 '0.0.0.0',  # Zeros
#             ]
#             bootp_client_macs: List[str] = [
#                 args.target_mac,  # Target MAC address
#             ]
#         for bootp_message_type in bootp_message_types:
#             for bootp_hardware_type in bootp_hardware_types:
#                 for bootp_hardware_length in bootp_hardware_lengths:
#                     for bootp_hop in bootp_hops:
#                         for bootp_flag in bootp_flags:
#                             for bootp_client_ip in bootp_client_ips:
#                                 for bootp_your_ip in bootp_your_ips:
#                                     for bootp_next_server_ip in bootp_next_server_ips:
#                                         for bootp_relay_agent_ip in bootp_relay_agent_ips:
#                                             for bootp_client_mac in bootp_client_macs:
#                                                 bootp_fields.append({
#                                                     'message_type': bootp_message_type,
#                                                     'hardware_type': bootp_hardware_type,
#                                                     'hardware_length': bootp_hardware_length,
#                                                     'hops': bootp_hop,
#                                                     'flags': bootp_flag,
#                                                     'client_ip': bootp_client_ip,
#                                                     'your_ip': bootp_your_ip,
#                                                     'next_server_ip': bootp_next_server_ip,
#                                                     'relay_agent_ip': bootp_relay_agent_ip,
#                                                     'client_mac': bootp_client_mac
#                                                 })
#         base.print_info('BOOTP message type: ', str(bootp_message_types))
#         base.print_info('BOOTP hardware type: ', str(bootp_hardware_types))
#         base.print_info('BOOTP hardware length: ', str(bootp_hardware_lengths))
#         base.print_info('BOOTP hops: ', str(bootp_hops))
#         base.print_info('BOOTP flags: ', str(bootp_flags))
#         base.print_info('BOOTP client ip: ', str(bootp_client_ips))
#         base.print_info('BOOTP your ip: ', str(bootp_your_ips))
#         base.print_info('BOOTP next server ip: ', str(bootp_next_server_ips))
#         base.print_info('BOOTP agent ip: ', str(bootp_relay_agent_ips))
#         base.print_info('BOOTP client mac: ', str(bootp_client_macs))
#         # endregion
#
#         # region DHCPv4
#         base.print_info('Make DHCPv4 tested parameters ...')
#         if args.all_tests:
#             # Long list
#             dhcp_server_identifiers: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#                 args.target_ip,  # Target IPv4 address
#                 '255.255.255.255',  # Broadcast IPv4 address
#                 '224.0.0.1',  # IPv4 multicast IPv4 address
#                 '0.0.0.0',  # Zeros
#             ]
#             dhcp_lease_times: List[int] = [
#                 0x0001,
#                 0xffff,  # Infinity
#             ]
#             dhcp_subnet_masks: List[str] = [
#                 '255.255.255.0'
#             ]
#             dhcp_routers: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#             ]
#             dhcp_dns_servers: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#             ]
#             dhcp_domains: List[bytes] = [
#                 b'local',
#             ]
#         else:
#             # Short list
#             dhcp_server_identifiers: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#             ]
#             dhcp_lease_times: List[int] = [
#                 0xffff,  # Infinity
#             ]
#             dhcp_subnet_masks: List[str] = [
#                 '255.255.255.0'
#             ]
#             dhcp_routers: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#             ]
#             dhcp_dns_servers: List[str] = [
#                 your_ip_address,  # Your IPv4 address
#             ]
#             dhcp_domains: List[bytes] = [
#                 b'local',
#             ]
#         for dhcp_server_identifier in dhcp_server_identifiers:
#             for dhcp_lease_time in dhcp_lease_times:
#                 for dhcp_subnet_mask in dhcp_subnet_masks:
#                     for dhcp_router in dhcp_routers:
#                         for dhcp_dns_server in dhcp_dns_servers:
#                             for dhcp_domain in dhcp_domains:
#                                 dhcp_options.append({
#                                     'server_identifier': dhcp_server_identifier,
#                                     'lease_time': dhcp_lease_time,
#                                     'subnet_mask': dhcp_subnet_mask,
#                                     'router': dhcp_router,
#                                     'dns_server': dhcp_dns_server,
#                                     'domain': dhcp_domain
#                                 })
#         base.print_info('DHCPv4 server identifier: ', str(dhcp_server_identifiers))
#         base.print_info('DHCPv4 lease time: ', str(dhcp_lease_times))
#         base.print_info('DHCPv4 subnet mask: ', str(dhcp_subnet_masks))
#         base.print_info('DHCPv4 router: ', str(dhcp_routers))
#         base.print_info('DHCPv4 dns server: ', str(dhcp_dns_servers))
#         base.print_info('DHCPv4 domain: ', str(dhcp_domains))
#         # endregion
#
#         # region Make all tested parameters
#         base.print_info('Make all permutations of tested parameters ...')
#         for link_layer in link_layer_fields:
#             for network_layer in network_layer_fields:
#                 for transport_layer in transport_layer_fields:
#                     for bootp in bootp_fields:
#                         for dhcp in dhcp_options:
#                             tested_parameters.append({
#                                 'Ethernet': link_layer,
#                                 'Network': network_layer,
#                                 'Transport': transport_layer,
#                                 'BOOTP': bootp,
#                                 'DHCP': dhcp
#                             })
#         base.print_info('All permutations are created, length of fuzzing packets: ',
#                         str(len(tested_parameters)))
#         # endregion
#
#         # endregion
#
#         # region Send
#         if args.send:
#             pcap_file: str = '/tmp/dhcp.pcap'
#             if isfile(pcap_file):
#                 remove(pcap_file)
#             start_tshark_over_ssh(ssh_user=args.target_ssh_user,
#                                   ssh_password=args.target_ssh_pass,
#                                   ssh_pkey=private_key,
#                                   ssh_host=args.target_ip,
#                                   os=args.target_os,
#                                   network_interface=args.target_interface)
#             sleep(1)
#             transaction: int = 0
#             dhcpv4_message_types: Dict[int, str] = {
#                 1: 'Discover',
#                 2: 'Offer',
#                 3: 'Request',
#                 4: 'Decline',
#                 5: 'ACK',
#                 6: 'NAK',
#                 7: 'Release',
#                 8: 'Inform',
#                 9: 'Force Renew',
#                 10: 'Lease Query',
#                 11: 'Lease Unassigned',
#                 12: 'Lease Unknown',
#                 13: 'Lease Active',
#                 14: 'Bulk Lease Query',
#                 15: 'Lease Query Done',
#                 16: 'Active Lease Query',
#                 17: 'Lease Query Status',
#                 18: 'TLS'
#             }
#             base.print_info('Length of tested parameters: ',
#                             str(len(tested_parameters) * len(dhcpv4_message_types.keys())))
#             for dhcpv4_message_type in dhcpv4_message_types.keys():
#                 for tested_index in range(0, len(tested_parameters), 1):
#                     for _ in range(3):
#                         raw_socket.send(make_reply(bootp_transaction_id=transaction,
#                                                    dhcpv4_message_type=dhcpv4_message_type))
#                     send_transactions[transaction] = [dhcpv4_message_type, tested_index]
#                     transaction += 1
#                     sleep(0.1)
#             sleep(3)
#             stop_tshark_over_ssh(ssh_user=args.target_ssh_user,
#                                  ssh_password=args.target_ssh_pass,
#                                  ssh_pkey=private_key,
#                                  ssh_host=args.target_ip,
#                                  os=args.target_os)
#             sleep(3)
#             if args.target_os == 'Windows':
#                 base.download_file_over_ssh(remote_path='C:\Windows\Temp\dhcp.pcap',
#                                             local_path=pcap_file,
#                                             ssh_user=args.target_ssh_user,
#                                             ssh_password=args.target_ssh_pass,
#                                             ssh_pkey=private_key,
#                                             ssh_host=args.target_ip)
#             else:
#                 base.download_file_over_ssh(remote_path=pcap_file,
#                                             local_path=pcap_file,
#                                             ssh_user=args.target_ssh_user,
#                                             ssh_password=args.target_ssh_pass,
#                                             ssh_pkey=private_key,
#                                             ssh_host=args.target_ip)
#             assert isfile(pcap_file), \
#                 'Can not download pcap file with DHCPv4 traffic over SSH'
#             base.print_info('Pcap file with DHCPv4 traffic is downloaded to: ', pcap_file)
#             packets = rdpcap(pcap_file)
#             for packet in packets:
#                 if packet.haslayer(BOOTP):
#                     sniff_transaction = packet[BOOTP].xid
#                     if sniff_transaction not in transactions:
#                         transactions.append(sniff_transaction)
#
#             for send_transaction in send_transactions.keys():
#                 if send_transaction in transactions:
#                     base.print_success('Tested index: ',
#                                        str(send_transactions[send_transaction][1]),
#                                        ' DHCPv4 message type: ',
#                                        dhcpv4_message_types[send_transactions[send_transaction][0]],
#                                        ' Tested parameters: ',
#                                        str(tested_parameters[send_transactions[send_transaction][1]]))
#                 else:
#                     base.print_error('Tested index: ',
#                                      str(send_transactions[send_transaction][1]),
#                                      ' DHCPv4 message type: ',
#                                      dhcpv4_message_types[send_transactions[send_transaction][0]],
#                                      ' Tested parameters: ',
#                                      str(tested_parameters[send_transactions[send_transaction][1]]))
#         # endregion
#
#         # region Sniff
#         else:
#             network_filters = {
#                 'Ethernet': {'source': args.target_mac, 'destination': 'ff:ff:ff:ff:ff:ff'},
#                 'IPv4': {'source-ip': '0.0.0.0', 'destination-ip': '255.255.255.255'},
#                 'UDP': {'source-port': 68, 'destination-port': 67}
#             }
#             dhclient_over_ssh(ssh_user=args.target_ssh_user,
#                               ssh_password=args.target_ssh_pass,
#                               ssh_pkey=private_key,
#                               ssh_host=args.target_ip,
#                               os=args.target_os,
#                               network_interface=args.target_interface)
#             sniff.start(protocols=['IPv4', 'UDP', 'DHCPv4'], prn=reply, filters=network_filters)
#         # endregion
#
#     except KeyboardInterrupt:
#         raw_socket.close()
#         base.print_info('Exit')
#         exit(0)
#
#     except AssertionError as Error:
#         raw_socket.close()
#         base.print_error(Error.args[0])
#         exit(1)
# # endregion
