#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
arp_fuzz.py: ARP fuzzing (arp_fuzz)
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Scripts.Fuzz.remote import RemoteTest
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import RawSend, RawEthernet
from argparse import ArgumentParser
from struct import pack
from socket import inet_aton
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
__script_name__ = 'ARP fuzzing (arp_fuzz)'
# endregion


# region Class ArpFuzz
class ArpFuzz:

    # region Variables
    _base: Base = Base(admin_only=True, available_platforms=['Linux', 'MacOS', 'Windows'])
    _eth: RawEthernet = RawEthernet()

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
        class Vlan8021Q:
            priority_dei_id: int = 0
            type: int = 0x0806

        @dataclass
        class ARP:
            hardware_type: int = 1
            protocol_type: int = 0x0800
            hardware_size: int = 6
            protocol_size: int = 4
            opcode: int = 1
            sender_mac: str = '12:34:56:78:90:ab'
            sender_ip: str = '192.168.1.1'
            target_mac: str = '12:34:56:78:90:ac'
            target_ip: str = '192.168.1.2'
            padding: bytes = b''

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
                0x0806,  # Address Resolution Protocol [RFC7042]
            ]
        # endregion

        # region Hardware types for ARP
        if all_tests:
            # Long list
            arp_hardware_types: List[int] = [
                0,  # reserved.	RFC 5494
                1,  # Ethernet.
                2,  # Experimental Ethernet.
                3,  # Amateur Radio AX.25.
                4,  # Proteon ProNET Token Ring.
                5,  # Chaos.
                6,  # IEEE 802.
                7,  # ARCNET.	RFC 1201
                8,  # Hyperchannel.
                9,  # Lanstar.
                10,  # Autonet Short Address.
                11,  # LocalTalk.
                12,  # LocalNet (IBM PCNet or SYTEK LocalNET).
                13,  # Ultra link.
                14,  # SMDS.
                15,  # Frame Relay.
                16,  # ATM, Asynchronous Transmission Mode.
                17,  # HDLC.
                18,  # Fibre Channel.	RFC 4338
                19,  # ATM, Asynchronous Transmission Mode.	RFC 2225
                20,  # Serial Line.
                21,  # ATM, Asynchronous Transmission Mode.
                22,  # MIL-STD-188-220.
                23,  # Metricom.
                24,  # IEEE 1394.1995.
                25,  # MAPOS.
                26,  # Twinaxial.
                27,  # EUI-64.
                28,  # HIPARP.	RFC 2834, RFC 2835
                29,  # IP and ARP over ISO 7816-3.
                30,  # ARPSec.
                31,  # IPsec tunnel.	RFC 3456
                32,  # Infiniband.	RFC 4391
                33,  # CAI, TIA-102 Project 25 Common Air Interface.
                34,  # Wiegand Interface.
                35,  # Pure IP.
                36,  # HW_EXP1	RFC 5494
                256  # HW_EXP2
            ]
        else:
            # Short list
            arp_hardware_types: List[int] = [
                1,  # Ethernet.
            ]
        # endregion

        # region Protocol types for ARP
        arp_protocol_types: List[int] = [
            0x0800  # IPv4
        ]
        # endregion

        # region Hardware sizes for ARP
        arp_hardware_sizes: List[int] = [
            0x06  # Length of MAC address
        ]
        # endregion

        # region Protocol sizes for ARP
        arp_protocol_sizes: List[int] = [
            0x04  # Length of IP address
        ]
        # endregion

        # region Opcodes for ARP
        if all_tests:
            # Long list
            arp_opcodes: List[int] = [
                0,  # reserved.	RFC 5494
                1,  # Request.	RFC 826, RFC 5227
                2,  # Reply.	RFC 826, RFC 1868, RFC 5227
                3,  # Request Reverse.	RFC 903
                4,  # Reply Reverse.	RFC 903
                5,  # DRARP Request.	RFC 1931
                6,  # DRARP Reply.	RFC 1931
                7,  # DRARP Error.	RFC 1931
                8,  # InARP Request.	RFC 1293
                9,  # InARP Reply.	RFC 1293
                10,  # ARP NAK.	RFC 1577
                11,  # MARS Request.
                12,  # MARS Multi.
                13,  # MARS MServ.
                14,  # MARS Join.
                15,  # MARS Leave.
                16,  # MARS NAK.
                17,  # MARS Unserv.
                18,  # MARS SJoin.
                19,  # MARS SLeave.
                20,  # MARS Grouplist Request.
                21,  # MARS Grouplist Reply.
                22,  # MARS Redirect Map.
                23,  # MAPOS UNARP.	RFC 2176
                24,  # OP_EXP1.	RFC 5494
                25  # OP_EXP2.	RFC 5494
            ]
        else:
            # Short list
            arp_opcodes: List[int] = [
                1,  # Request.	RFC 826, RFC 5227
                2,  # Reply.	RFC 826, RFC 1868, RFC 5227
            ]
        # endregion

        # region Sender and target MAC and IP addresses for ARP
        if all_tests:
            # Long list
            arp_sender_mac_addresses: List[str] = [
                self._your.mac_address,  # Your MAC address
                self._gateway.mac_address,  # Gateway MAC address
                self._target.mac_address,  # Target MAC address
                '00:00:00:00:00:00',  # Empty MAC address
                'ff:ff:ff:ff:ff:ff'  # Broadcast MAC address
            ]
            arp_sender_ip_addresses: List[str] = [
                self._your.ipv4_address,  # Your IP address
                self._gateway.ipv4_address,  # Gateway IP address
                self._target.ipv4_address,  # Target IP address
                '0.0.0.0',  # Empty IP address
                '255.255.255.255'  # Broadcast IP address
            ]
            arp_target_mac_addresses: List[str] = [
                self._your.mac_address,  # Your MAC address
                self._gateway.mac_address,  # Gateway MAC address
                self._target.mac_address,  # Target MAC address
                '00:00:00:00:00:00',  # Empty MAC address
                'ff:ff:ff:ff:ff:ff'  # Broadcast MAC address
            ]
            arp_target_ip_addresses: List[str] = [
                self._your.ipv4_address,  # Your IP address
                self._gateway.ipv4_address,  # Gateway IP address
                self._target.ipv4_address,  # Target IP address
                '0.0.0.0',  # Empty IP address
                '255.255.255.255'  # Broadcast IP address
            ]
        else:
            # Short list
            arp_sender_mac_addresses: List[str] = [
                self._your.mac_address,  # Your MAC address
            ]
            arp_sender_ip_addresses: List[str] = [
                self._gateway.ipv4_address,  # Gateway IP address
            ]
            arp_target_mac_addresses: List[str] = [
                self._target.mac_address,  # Target MAC address
            ]
            arp_target_ip_addresses: List[str] = [
                self._target.ipv4_address,  # Target IP address
            ]
        # endregion
        
        # region Print test parameters
        self._base.print_info('Ethernet source MAC addresses: ', str(ethernet_source_mac_addresses))
        self._base.print_info('Ethernet destination MAC addresses: ', str(ethernet_destination_mac_addresses))
        self._base.print_info('Ethernet protocol types: ', str(ethernet_types))

        self._base.print_info('ARP hardware types: ', str(arp_hardware_types))
        self._base.print_info('ARP protocol types: ', str(arp_protocol_types))
        self._base.print_info('ARP hardware sizes: ', str(arp_hardware_sizes))
        self._base.print_info('ARP protocol sizes: ', str(arp_protocol_sizes))
        self._base.print_info('ARP opcodes: ', str(arp_opcodes))
        self._base.print_info('ARP sender MAC addresses: ', str(arp_sender_mac_addresses))
        self._base.print_info('ARP sender IP addresses: ', str(arp_sender_ip_addresses))
        self._base.print_info('ARP target MAC addresses: ', str(arp_target_mac_addresses))
        self._base.print_info('ARP target IP addresses: ', str(arp_target_ip_addresses))
        # endregion
        
        # region Network parameters permutations
        self._base.print_info('Make all permutations of tested parameters .....')
        for eth_src_mac in ethernet_source_mac_addresses:
            for eth_dst_mac in ethernet_destination_mac_addresses:
                for eth_type in ethernet_types:
                    for arp_hardware_type in arp_hardware_types:
                        for arp_protocol_type in arp_protocol_types:
                            for arp_hardware_size in arp_hardware_sizes:
                                for arp_protocol_size in arp_protocol_sizes:
                                    for arp_opcode in arp_opcodes:
                                        for arp_sender_mac in arp_sender_mac_addresses:
                                            for arp_sender_ip in arp_sender_ip_addresses:
                                                for arp_target_mac in arp_target_mac_addresses:
                                                    for arp_target_ip in arp_target_ip_addresses:

                                                        params = self.TestParameters()
                                                        params.EthernetHeader = self.TestParameters.EthernetHeader()
                                                        params.ARP = self.TestParameters.ARP()
                                    
                                                        params.EthernetHeader.source_address = eth_src_mac
                                                        params.EthernetHeader.destination_address = eth_dst_mac
                                                        params.EthernetHeader.type = eth_type
                                                        
                                                        params.ARP.hardware_type = arp_hardware_type
                                                        params.ARP.protocol_type = arp_protocol_type
                                                        params.ARP.hardware_size = arp_hardware_size
                                                        params.ARP.protocol_size = arp_protocol_size
                                                        params.ARP.opcode = arp_opcode
                                                        params.ARP.sender_mac = arp_sender_mac
                                                        params.ARP.sender_ip = arp_sender_ip
                                                        params.ARP.target_mac = arp_target_mac
                                                        params.ARP.target_ip = arp_target_ip
                                    
                                                        self._test_parameters.append(params)
        self._base.print_info('All permutations are created, length of fuzzing packets: ', 
                              str(len(self._test_parameters)))
        # endregion

        try:

            # region Check current Gateway MAC address
            remote_test: RemoteTest = RemoteTest(target=self._target, gateway=self._gateway,
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
                
                sender_mac: bytes = self._eth.convert_mac(mac_address=self._test_parameters[index].ARP.sender_mac)
                sender_ip: bytes = inet_aton(self._test_parameters[index].ARP.sender_ip)
                target_mac: bytes = self._eth.convert_mac(mac_address=self._test_parameters[index].ARP.target_mac)
                target_ip: bytes = inet_aton(self._test_parameters[index].ARP.target_ip)

                arp_packet: bytes = pack('!H', self._test_parameters[index].ARP.hardware_type)
                arp_packet += pack('!H', self._test_parameters[index].ARP.protocol_type)
                arp_packet += pack('!B', self._test_parameters[index].ARP.hardware_size)
                arp_packet += pack('!B', self._test_parameters[index].ARP.protocol_size)
                arp_packet += pack('!H', self._test_parameters[index].ARP.opcode)

                arp_packet += sender_mac + pack('!' '4s', sender_ip)
                arp_packet += target_mac + pack('!' '4s', target_ip)

                # eth_header: bytes = \
                #     self._eth.make_header(source_mac=self._test_parameters[index].EthernetHeader.source_address,
                #                           destination_mac=self._test_parameters[index].EthernetHeader.destination_address,
                #                           network_type=self._test_parameters[index].EthernetHeader.type)
                #
                # packet: bytes = eth_header + arp_packet
                #
                # self._raw_send.send_packet(packet=packet, count=self._number_of_packets,
                #                            delay=self._interval_between_packets)
                #
                # remote_test.check_ipv4_gateway_mac_address_over_ssh(test_parameters_index=index)

                eth_header: bytes = \
                    self._eth.make_header(source_mac=self._test_parameters[index].EthernetHeader.source_address,
                                          destination_mac=self._test_parameters[index].EthernetHeader.destination_address,
                                          network_type=0x8100)

                vlan_header: bytes = pack('!H', 0)
                vlan_header += pack('!H', self._test_parameters[index].EthernetHeader.type)

                packet: bytes = eth_header + vlan_header + arp_packet

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
    base: Base = Base(admin_only=True, available_platforms=['Linux', 'MacOS', 'Windows'])
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
        arp_fuzz: ArpFuzz = ArpFuzz(network_interface=current_network_interface)
        arp_fuzz.start(target_ip=args.target_ip,
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
