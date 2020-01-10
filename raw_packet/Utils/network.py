# region Description
"""
test_network.py: Class for creating and parsing network packets for Raw-packet project
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from random import choice, randint
from struct import pack, unpack, error as struct_error
from binascii import unhexlify, hexlify
from array import array
from socket import error as sock_error, inet_aton, inet_ntoa, inet_pton, htons, IPPROTO_TCP, IPPROTO_UDP, AF_INET6
from socket import socket, AF_PACKET, SOCK_RAW, inet_ntop, IPPROTO_ICMPV6
from re import search
from time import time
from typing import Dict, List, Union, Tuple, Any
from traceback import format_tb
from enum import Enum
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.1.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Raw Ethernet
class RawEthernet:
    """
    Class for making and parsing Ethernet header
    """
    # +---------------------------------------------------------------+
    # |       Ethernet destination address (first 32 bits)            |
    # +-------------------------------+-------------------------------+
    # | Ethernet dest (last 16 bits)  |Ethernet source (first 16 bits)|
    # +-------------------------------+-------------------------------+
    # |       Ethernet source address (last 32 bits)                  |
    # +-------------------------------+-------------------------------+
    # |        Type code              |                               |
    # +-------------------------------+-------------------------------+

    # region Properties

    # Set length of Ethernet header
    header_length: int = 14

    # List of MAC address prefixes
    macs: List[str] = list()

    # Init Raw-packet Base class
    base: Base = Base()

    # endregion

    def __init__(self):
        """
        Init
        """
        self.macs.append('3c:d9:2b')  # Hewlett Packard
        self.macs.append('9c:8e:99')  # Hewlett Packard
        self.macs.append('b4:99:ba')  # Hewlett Packard
        self.macs.append('00:50:ba')  # Hewlett Packard
        self.macs.append('00:11:0a')  # Hewlett Packard
        self.macs.append('00:11:85')  # Hewlett Packard
        self.macs.append('00:12:79')  # Hewlett Packard
        self.macs.append('00:13:21')  # Hewlett Packard
        self.macs.append('00:14:38')  # Hewlett Packard
        self.macs.append('00:14:c2')  # Hewlett Packard
        self.macs.append('00:15:60')  # Hewlett Packard
        self.macs.append('00:16:35')  # Hewlett Packard
        self.macs.append('00:17:08')  # Hewlett Packard
        self.macs.append('00:18:fe')  # Hewlett Packard
        self.macs.append('00:19:bb')  # Hewlett Packard
        self.macs.append('00:1a:4b')  # Hewlett Packard
        self.macs.append('00:1b:78')  # Hewlett Packard
        self.macs.append('00:1c:c4')  # Hewlett Packard
        self.macs.append('00:1e:0b')  # Hewlett Packard
        self.macs.append('00:1f:29')  # Hewlett Packard
        self.macs.append('00:21:5a')  # Hewlett Packard
        self.macs.append('00:22:64')  # Hewlett Packard
        self.macs.append('00:23:7d')  # Hewlett Packard
        self.macs.append('00:24:81')  # Hewlett Packard
        self.macs.append('00:25:b3')  # Hewlett Packard
        self.macs.append('00:26:55')  # Hewlett Packard
        self.macs.append('00:0d:88')  # D-Link Corporation
        self.macs.append('00:0f:3d')  # D-Link Corporation
        self.macs.append('00:13:46')  # D-Link Corporation
        self.macs.append('00:15:e9')  # D-Link Corporation
        self.macs.append('00:17:9a')  # D-Link Corporation
        self.macs.append('00:19:5b')  # D-Link Corporation
        self.macs.append('00:1b:11')  # D-Link Corporation
        self.macs.append('00:1c:f0')  # D-Link Corporation
        self.macs.append('00:1e:58')  # D-Link Corporation
        self.macs.append('00:21:91')  # D-Link Corporation
        self.macs.append('00:22:b0')  # D-Link Corporation
        self.macs.append('00:24:01')  # D-Link Corporation
        self.macs.append('00:26:5a')  # D-Link Corporation
        self.macs.append('00:0d:88')  # D-Link Corporation
        self.macs.append('00:0f:3d')  # D-Link Corporation
        self.macs.append('00:00:0c')  # Cisco Systems, Inc
        self.macs.append('00:01:42')  # Cisco Systems, Inc
        self.macs.append('00:01:43')  # Cisco Systems, Inc
        self.macs.append('00:01:63')  # Cisco Systems, Inc
        self.macs.append('00:01:64')  # Cisco Systems, Inc
        self.macs.append('00:01:96')  # Cisco Systems, Inc
        self.macs.append('00:01:97')  # Cisco Systems, Inc
        self.macs.append('00:01:c7')  # Cisco Systems, Inc
        self.macs.append('00:01:c9')  # Cisco Systems, Inc
        self.macs.append('00:02:16')  # Cisco Systems, Inc
        self.macs.append('00:02:17')  # Cisco Systems, Inc
        self.macs.append('00:02:4a')  # Cisco Systems, Inc
        self.macs.append('00:02:4b')  # Cisco Systems, Inc
        self.macs.append('00:02:7d')  # Cisco Systems, Inc
        self.macs.append('00:02:7e')  # Cisco Systems, Inc
        self.macs.append('d0:d0:fd')  # Cisco Systems, Inc
        self.macs.append('d4:8c:b5')  # Cisco Systems, Inc
        self.macs.append('d4:a0:2a')  # Cisco Systems, Inc
        self.macs.append('d4:d7:48')  # Cisco Systems, Inc
        self.macs.append('d8:24:bd')  # Cisco Systems, Inc
        self.macs.append('08:63:61')  # Huawei Technologies Co., Ltd
        self.macs.append('08:7a:4c')  # Huawei Technologies Co., Ltd
        self.macs.append('0c:37:dc')  # Huawei Technologies Co., Ltd
        self.macs.append('0c:96:bf')  # Huawei Technologies Co., Ltd
        self.macs.append('10:1b:54')  # Huawei Technologies Co., Ltd
        self.macs.append('10:47:80')  # Huawei Technologies Co., Ltd
        self.macs.append('10:c6:1f')  # Huawei Technologies Co., Ltd
        self.macs.append('20:f3:a3')  # Huawei Technologies Co., Ltd
        self.macs.append('24:69:a5')  # Huawei Technologies Co., Ltd
        self.macs.append('28:31:52')  # Huawei Technologies Co., Ltd
        self.macs.append('00:1b:63')  # Apple Inc
        self.macs.append('00:1c:b3')  # Apple Inc
        self.macs.append('00:1d:4f')  # Apple Inc
        self.macs.append('00:1e:52')  # Apple Inc
        self.macs.append('00:1e:c2')  # Apple Inc
        self.macs.append('00:1f:5b')  # Apple Inc
        self.macs.append('00:1f:f3')  # Apple Inc
        self.macs.append('00:21:e9')  # Apple Inc
        self.macs.append('00:22:41')  # Apple Inc
        self.macs.append('00:23:12')  # Apple Inc
        self.macs.append('00:23:32')  # Apple Inc
        self.macs.append('00:23:6c')  # Apple Inc
        self.macs.append('00:23:df')  # Apple Inc
        self.macs.append('00:24:36')  # Apple Inc
        self.macs.append('00:25:00')  # Apple Inc
        self.macs.append('00:25:4b')  # Apple Inc
        self.macs.append('00:25:bc')  # Apple Inc
        self.macs.append('00:26:08')  # Apple Inc
        self.macs.append('00:26:4a')  # Apple Inc
        self.macs.append('00:26:b0')  # Apple Inc
        self.macs.append('00:26:bb')  # Apple Inc
        self.macs.append('00:11:75')  # Intel Corporate
        self.macs.append('00:13:e8')  # Intel Corporate
        self.macs.append('00:13:02')  # Intel Corporate
        self.macs.append('00:02:b3')  # Intel Corporate
        self.macs.append('00:03:47')  # Intel Corporate
        self.macs.append('00:04:23')  # Intel Corporate
        self.macs.append('00:0c:f1')  # Intel Corporate
        self.macs.append('00:0e:0c')  # Intel Corporate
        self.macs.append('00:0e:35')  # Intel Corporate
        self.macs.append('00:12:f0')  # Intel Corporate
        self.macs.append('00:13:02')  # Intel Corporate
        self.macs.append('00:13:20')  # Intel Corporate
        self.macs.append('00:13:ce')  # Intel Corporate
        self.macs.append('00:13:e8')  # Intel Corporate
        self.macs.append('00:15:00')  # Intel Corporate
        self.macs.append('00:15:17')  # Intel Corporate
        self.macs.append('00:16:6f')  # Intel Corporate
        self.macs.append('00:16:76')  # Intel Corporate
        self.macs.append('00:16:ea')  # Intel Corporate
        self.macs.append('00:16:eb')  # Intel Corporate
        self.macs.append('00:18:de')  # Intel Corporate

    def __enter__(self):
        """
        Enter
        :return: self
        """
        return self

    def make_random_mac(self) -> str:
        """
        Make random MAC address
        :return: Random MAC address string (example: '01:23:45:67:89:0a')
        """
        mac_prefix = choice(self.macs)
        mac_suffix = ':'.join('{0:02x}'.format(randint(0x00, 0xff), 'x') for _ in range(3))
        return mac_prefix + ':' + mac_suffix

    def convert_mac(self,
                    mac_address: Union[str, bytes] = '01:23:45:67:89:0a',
                    exit_on_failure: bool = True,
                    exit_code: int = 41,
                    quiet: bool = False) -> Union[None, bytes, str]:
        """
        Convert MAC address string or bytes to bytes
        :param mac_address: MAC address string or bytes (example: '01:23:45:67:89:0a' or b'\x01#Eg\x89\n')
        :param exit_on_failure: Exit in case of error (default: True)
        :param exit_code: Set exit code integer (default: 41)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Result bytes or string (example: b'\x01#Eg\x89\n' or '01:23:45:67:89:0a') or None if error
        """
        try:
            if len(mac_address) == 17 and type(mac_address) == str:
                mac_address: str = str(mac_address).lower()
                assert search('([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', mac_address), \
                    'Bad MAC address: ' + self.base.error_text(str(mac_address))
                return unhexlify(mac_address.replace(':', ''))

            elif len(mac_address) == 6 and type(mac_address) == bytes:
                result_mac_address: str = ''
                for byte_of_address in mac_address:
                    result_mac_address += '{:02x}'.format(byte_of_address) + ':'
                return result_mac_address[:-1].lower()

            else:
                raise AssertionError('Bad MAC address length: ' + self.base.error_text(str(len(mac_address))))

        except AssertionError as Error:
            if not quiet:
                self.base.print_error(Error.args[0])
            if exit_on_failure:
                exit(exit_code)
            else:
                return None

    def get_mac_prefix(self,
                       mac_address: Union[str, bytes] = '01:23:45:67:89:0a',
                       prefix_length: int = 3,
                       exit_on_failure: bool = True,
                       exit_code: int = 42,
                       quiet: bool = False) -> Union[None, str]:
        """
        Get MAC address prefix string
        :param mac_address: MAC address string or bytes (example: 'ab:c3:45:67:89:0a' or b'\xab\xc3Eg\x89\n')
        :param prefix_length: Length bytes of prefix (default: 3)
        :param exit_on_failure: Exit in case of error (default: True)
        :param exit_code: Set exit code integer (default: 42)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: MAC address prefix string (example: 'ABC345') or None if error
        """
        try:
            if len(mac_address) == 17 and type(mac_address) == str:
                mac_address: str = str(mac_address).lower()
                assert search('([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', mac_address), \
                    'Bad MAC address: ' + self.base.error_text(str(mac_address))
                result_mac_address: str = mac_address.replace(':', '')
                return result_mac_address[:(prefix_length * 2)].upper()

            elif len(mac_address) == 6 and type(mac_address) == bytes:
                result_mac_address: str = ''
                for byte_of_address in mac_address[0:prefix_length]:
                    result_mac_address += '{:02x}'.format(byte_of_address)
                return result_mac_address.upper()

            else:
                raise AssertionError('Bad MAC address length: ' + self.base.error_text(str(len(mac_address))))

        except AssertionError as Error:
            if not quiet:
                self.base.print_error(Error.args[0])
            if exit_on_failure:
                exit(exit_code)
            else:
                return None

    def parse_header(self,
                     packet: bytes,
                     exit_on_failure: bool = False,
                     exit_code: int = 43,
                     quiet: bool = True) -> Union[None, Dict[str, Union[int, str]]]:
        """
        Parse Ethernet packet
        :param packet: Bytes of packet
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 43)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Parsed Ethernet header dictionary (example: {'destination': '01:23:45:67:89:0a', 'source': '01:23:45:67:89:0a', 'type': 2048}) or None if error
        """
        try:
            assert not len(packet) != self.header_length, \
                'Bad packet length: ' + self.base.error_text(str(len(packet))) + \
                ' normal Ethernet header length: ' + self.base.success_text(str(self.header_length))

            ethernet_detailed = unpack('!' '6s' '6s' 'H', packet)

            return {
                'destination': self.convert_mac(mac_address=ethernet_detailed[0],
                                                exit_on_failure=exit_on_failure,
                                                exit_code=exit_code,
                                                quiet=quiet),
                'source':      self.convert_mac(mac_address=ethernet_detailed[1],
                                                exit_on_failure=exit_on_failure,
                                                exit_code=exit_code,
                                                quiet=quiet),
                'type':        int(ethernet_detailed[2])
            }

        except AssertionError as Error:
            error_text = Error.args[0]

        except IndexError:
            error_text = 'Failed to parse Ethernet header!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_header(self,
                    source_mac: str = '01:23:45:67:89:0a',
                    destination_mac: str = '01:23:45:67:89:0b',
                    network_type: int = 2048,
                    exit_on_failure: bool = False,
                    exit_code: int = 44,
                    quiet: bool = False) -> Union[None, bytes]:
        """
        Make Ethernet packet header
        :param source_mac: Source MAC address string (example: '01:23:45:67:89:0a')
        :param destination_mac: Destination MAC address string (example: '01:23:45:67:89:0b')
        :param network_type: Network type integer (example: 2048 - IPv4, 2054 - ARP, 34525 - IPv6)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 44)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        error_text: str = 'Failed to make Ethernet header!'
        packet: bytes = b''
        try:
            packet += self.convert_mac(exit_on_failure=exit_on_failure,
                                       exit_code=exit_code,
                                       quiet=quiet,
                                       mac_address=destination_mac)
            packet += self.convert_mac(exit_on_failure=exit_on_failure,
                                       exit_code=exit_code,
                                       quiet=quiet,
                                       mac_address=source_mac)
            return packet + pack('!H', network_type)

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'destination_mac' in traceback_text:
                error_text += ' Bad destination MAC address: ' + self.base.error_text(str(destination_mac)) + \
                              ' example MAC address: ' + self.base.info_text('01:23:45:67:89:0a')
            if 'source_mac' in traceback_text:
                error_text += ' Bad source MAC address: ' + self.base.error_text(str(source_mac)) + \
                              ' example MAC address: ' + self.base.info_text('01:23:45:67:89:0a')

        except struct_error:
            error_text += ' Bad network type: ' + self.base.error_text(str(network_type)) + \
                          ' example network type: ' + self.base.info_text(str('2048 - IPv4, 2054 - ARP, 34525 - IPv6'))

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def __exit__(self, exc_type, exc_val, exc_tb):
        del self.macs[:]
# endregion


# region Raw ARP
class RawARP:
    """
    Class for making and parsing ARP packet
    """
    # 0        7        15       23       31
    # +--------+--------+--------+--------+
    # |       HT        |        PT       |
    # +--------+--------+--------+--------+
    # |  HAL   |  PAL   |        OP       |
    # +--------+--------+--------+--------+
    # |         S_HA (bytes 0-3)          |
    # +--------+--------+--------+--------+
    # | S_HA (bytes 4-5)|S_L32 (bytes 0-1)|
    # +--------+--------+--------+--------+
    # |S_L32 (bytes 2-3)|S_NID (bytes 0-1)|
    # +--------+--------+--------+--------+
    # |         S_NID (bytes 2-5)         |
    # +--------+--------+--------+--------+
    # |S_NID (bytes 6-7)| T_HA (bytes 0-1)|
    # +--------+--------+--------+--------+
    # |         T_HA (bytes 3-5)          |
    # +--------+--------+--------+--------+
    # |         T_L32 (bytes 0-3)         |
    # +--------+--------+--------+--------+
    # |         T_NID (bytes 0-3)         |
    # +--------+--------+--------+--------+
    # |         T_NID (bytes 4-7)         |
    # +--------+--------+--------+--------+

    # region Properties

    # Set ARP packet type
    packet_type: int = 2054

    # Set ARP packet length
    packet_length: int = 28

    # Init Raw-packet Base class
    base: Base = Base()

    # Init Raw Ethernet class
    eth: RawEthernet = RawEthernet()

    # endregion

    def parse_packet(self,
                     packet: bytes,
                     exit_on_failure: bool = False,
                     exit_code: int = 45,
                     quiet: bool = False) -> Union[None, Dict[str, Union[int, str]]]:
        """
        Parse ARP packet
        :param packet: Bytes of packet
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 45)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Parsed ARP packet dictionary or None if error
        """
        error_text: str = 'Failed to parse ARP packet!'
        try:
            assert not len(packet) != RawARP.packet_length, \
                ' Bad packet length: ' + self.base.error_text(str(len(packet))) + \
                ' normal ARP packet length: ' + self.base.success_text(str(RawARP.packet_length))

            arp_detailed = unpack('!' '2H' '2B' 'H' '6s' '4s' '6s' '4s', packet)

            return {
                'hardware-type': int(arp_detailed[0]),
                'protocol-type': int(arp_detailed[1]),
                'hardware-size': int(arp_detailed[2]),
                'protocol-size': int(arp_detailed[3]),
                'opcode':        int(arp_detailed[4]),
                'sender-mac':    self.eth.convert_mac(mac_address=arp_detailed[5],
                                                      exit_on_failure=exit_on_failure,
                                                      exit_code=exit_code,
                                                      quiet=quiet),
                'sender-ip':     inet_ntoa(arp_detailed[6]),
                'target-mac':    self.eth.convert_mac(mac_address=arp_detailed[7],
                                                      exit_on_failure=exit_on_failure,
                                                      exit_code=exit_code,
                                                      quiet=quiet),
                'target-ip':     inet_ntoa(arp_detailed[8])
            }

        except AssertionError as Error:
            error_text += Error.args[0]

        except IndexError:
            pass

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_packet(self,
                    ethernet_src_mac: str = '01:23:45:67:89:0a',
                    ethernet_dst_mac: str = '01:23:45:67:89:0b',
                    sender_mac: str = '01:23:45:67:89:0a',
                    sender_ip: str = '192.168.1.1',
                    target_mac: str = '01:23:45:67:89:0b',
                    target_ip: str = '192.168.1.2',
                    opcode: int = 1,
                    hardware_type: int = 1,
                    protocol_type: int = 2048,
                    hardware_size: int = 6,
                    protocol_size: int = 4,
                    exit_on_failure: bool = False,
                    exit_code: int = 46,
                    quiet: bool = False) -> Union[None, bytes]:
        """
        Make ARP packet bytes
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param sender_mac: Sender MAC address string in ARP packet (example: '01:23:45:67:89:0a')
        :param sender_ip: Sender IP address string in ARP packet (example: '192.168.1.1')
        :param target_mac: Target MAC address string in ARP packet (example: '01:23:45:67:89:0b')
        :param target_ip: Target IP address string in ARP packet (example: '192.168.1.2')
        :param opcode: Operation code integer (example: 1 - request, 2 - response)
        :param hardware_type: Hardware type integer (default: 1 - Ethernet)
        :param protocol_type: Protocol type integer (default: 2048 - IPv4 protocol)
        :param hardware_size: Size of hardware address integer (default: 6)
        :param protocol_size: Size of network protocol address integer (default: 4)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 46)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of ARP packet or None if error
        """
        error_text: str = 'Failed to make ARP packet!'
        arp_packet: bytes = b''
        try:
            sender_ip = inet_aton(sender_ip)
            target_ip = inet_aton(target_ip)
            sender_mac = self.eth.convert_mac(mac_address=sender_mac,
                                              exit_on_failure=exit_on_failure,
                                              exit_code=exit_code,
                                              quiet=quiet)
            target_mac = self.eth.convert_mac(mac_address=target_mac,
                                              exit_on_failure=exit_on_failure,
                                              exit_code=exit_code,
                                              quiet=quiet)

            arp_packet += pack('!H', hardware_type)
            arp_packet += pack('!H', protocol_type)
            arp_packet += pack('!B', hardware_size)
            arp_packet += pack('!B', protocol_size)
            arp_packet += pack('!H', opcode)
            arp_packet += sender_mac + pack('!' '4s', sender_ip)
            arp_packet += target_mac + pack('!' '4s', target_ip)

            eth_header = self.eth.make_header(source_mac=ethernet_src_mac,
                                              destination_mac=ethernet_dst_mac,
                                              network_type=RawARP.packet_type,
                                              exit_on_failure=exit_on_failure,
                                              exit_code=exit_code,
                                              quiet=quiet)
            return eth_header + arp_packet

        except TypeError:
            pass

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'opcode' in traceback_text:
                error_text += ' Bad opcode: ' + self.base.error_text(str(opcode)) + \
                              ' acceptable opcodes: ' + self.base.info_text('1 - request, 2 - response')
            if 'hardware_type' in traceback_text:
                error_text += ' Bad hardware type: ' + self.base.error_text(str(hardware_type)) + \
                              ' acceptable hardware type: ' + self.base.info_text('1 - Ethernet')
            if 'protocol_type' in traceback_text:
                error_text += ' Bad protocol type: ' + self.base.error_text(str(protocol_type)) + \
                              ' acceptable protocol type: ' + self.base.info_text('2048 - IPv4 protocol')
            if 'hardware_size' in traceback_text:
                error_text += ' Bad hardware size: ' + self.base.error_text(str(hardware_size)) + \
                              ' acceptable hardware size: ' + self.base.info_text('6')
            if 'protocol_size' in traceback_text:
                error_text += ' Bad protocol size: ' + self.base.error_text(str(protocol_size)) + \
                              ' acceptable protocol size: ' + self.base.info_text('4')

        except OSError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'sender_ip' in traceback_text:
                error_text += ' Bad sender IP: ' + self.base.error_text(str(sender_ip))
            if 'target_ip' in traceback_text:
                error_text += ' Bad target IP: ' + self.base.error_text(str(target_ip))

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_request(self,
                     ethernet_src_mac: str = '01:23:45:67:89:0a',
                     ethernet_dst_mac: str = '01:23:45:67:89:0b',
                     sender_mac: str = '01:23:45:67:89:0a',
                     sender_ip: str = '192.168.1.1',
                     target_mac: str = '01:23:45:67:89:0b',
                     target_ip: str = '192.168.1.2',
                     exit_on_failure: bool = False,
                     exit_code: int = 47,
                     quiet: bool = False) -> Union[None, bytes]:
        """
        Make ARP request packet bytes
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param sender_mac: Sender MAC address string in ARP packet (example: '01:23:45:67:89:0a')
        :param sender_ip: Sender IP address string in ARP packet (example: '192.168.1.1')
        :param target_mac: Target MAC address string in ARP packet (example: '01:23:45:67:89:0b')
        :param target_ip: Target IP address string in ARP packet (example: '192.168.1.2')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 47)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of ARP request packet or None if error
        """
        return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                ethernet_dst_mac=ethernet_dst_mac,
                                sender_mac=sender_mac,
                                sender_ip=sender_ip,
                                target_mac=target_mac,
                                target_ip=target_ip,
                                opcode=1,
                                exit_on_failure=exit_on_failure,
                                exit_code=exit_code,
                                quiet=quiet)

    def make_response(self,
                      ethernet_src_mac: str = '01:23:45:67:89:0a',
                      ethernet_dst_mac: str = '01:23:45:67:89:0b',
                      sender_mac: str = '01:23:45:67:89:0a',
                      sender_ip: str = '192.168.1.1',
                      target_mac: str = '01:23:45:67:89:0b',
                      target_ip: str = '192.168.1.2',
                      exit_on_failure: bool = False,
                      exit_code: int = 48,
                      quiet: bool = False) -> Union[None, bytes]:
        """
        Make ARP response packet bytes
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param sender_mac: Sender MAC address string in ARP packet (example: '01:23:45:67:89:0a')
        :param sender_ip: Sender IP address string in ARP packet (example: '192.168.1.1')
        :param target_mac: Target MAC address string in ARP packet (example: '01:23:45:67:89:0b')
        :param target_ip: Target IP address string in ARP packet (example: '192.168.1.2')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 48)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of ARP response packet or None if error
        """
        return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                ethernet_dst_mac=ethernet_dst_mac,
                                sender_mac=sender_mac,
                                sender_ip=sender_ip,
                                target_mac=target_mac,
                                target_ip=target_ip,
                                opcode=2,
                                exit_on_failure=exit_on_failure,
                                exit_code=exit_code,
                                quiet=quiet)

# endregion


# region Raw IPv4
class RawIPv4:
    """
    Class for making and parsing IPv4 header
    """
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-------+-------+---------------+-------------------------------+
    # |Version|  IHL  |Type of Service|          Total Length         |
    # +-------+-------+---------------+-----+-------------------------+
    # |         Identification        |Flags|      Fragment Offset    |
    # +---------------+---------------+-----+-------------------------+
    # |  Time to Live |    Protocol   |         Header Checksum       |
    # +---------------+---------------+-------------------------------+
    # |                       Source Address                          |
    # +---------------------------------------------------------------+
    # |                    Destination Address                        |
    # +-----------------------------------------------+---------------+
    # |                    Options                    |    Padding    |
    # +-----------------------------------------------+---------------+

    # region Properties

    # Set Header type
    header_type: int = 2048

    # Set Header minimal length
    header_length: int = 20

    # Set Internet protocol version
    version: int = 4

    # Init Raw-packet Base class
    base: Base = Base()

    # endregion

    @staticmethod
    def make_random_ip() -> str:
        """
        Get random IPv4 address string
        :return: Random IPv4 address string (example: '123.123.123.123')
        """
        return '.'.join(str(randint(0, 255)) for _ in range(4))

    @staticmethod
    def _checksum(packet: bytes) -> int:
        """
        Calculate packet checksum
        :param packet: Bytes of packet
        :return: Result checksum
        """
        if len(packet) % 2 == 1:
            packet += '\0'
        s = sum(array('H', packet))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s >> 8) & 0xff) | s << 8) & 0xffff

    def parse_header(self,
                     packet: bytes,
                     exit_on_failure: bool = False,
                     exit_code: int = 49,
                     quiet: bool = True) -> Union[None, Dict[str, Union[int, str]]]:
        """
        Parse IPv4 header
        :param packet: Bytes of packet
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 49)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Parsed IPv4 header dictionary (example: {'version': 4, 'length': 5, 'dscp_ecn': 0, 'total-length': 28, 'identification': 36143, 'flags': 0, 'fragment-offset': 0, 'time-to-live': 64, 'protocol': 17, 'checksum': 27214, 'source-ip': '192.168.1.1', 'destination-ip': '192.168.1.2'}) or None if error
        """
        error_text: str = 'Failed to parse IPv4 header!'
        try:
            assert not len(packet) < self.header_length, \
                ' Bad packet length: ' + self.base.error_text(str(len(packet))) + \
                ' minimal IPv4 header length: ' + self.base.info_text(str(self.header_length))

            version_and_length = int(unpack('!B', packet[:1])[0])
            version = int(int(version_and_length & 0b11110000) >> 4)
            length = int(int(version_and_length) & 0b00001111)

            assert version == self.version, ' Bad IP version: ' + self.base.error_text(str(version))

            ip_detailed = unpack('!' 'B' '3H' '2B' 'H' '4s' '4s', packet[1:self.header_length])

            return {
                'version':         version,
                'length':          length,
                'dscp_ecn':        int(ip_detailed[0]),
                'total-length':    int(ip_detailed[1]),
                'identification':  int(ip_detailed[2]),
                'flags':           int(int(int(ip_detailed[3]) & 0b1110000000000000) >> 3),
                'fragment-offset': int(int(ip_detailed[3]) & 0b0001111111111111),
                'time-to-live':    int(ip_detailed[4]),
                'protocol':        int(ip_detailed[5]),
                'checksum':        int(ip_detailed[6]),
                'source-ip':       inet_ntoa(ip_detailed[7]),
                'destination-ip':  inet_ntoa(ip_detailed[8])
            }

        except AssertionError as Error:
            error_text += Error.args[0]

        except IndexError:
            pass

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_header(self,
                    source_ip: str = '192.168.1.1',
                    destination_ip: str = '192.168.1.2',
                    data_len: int = 0,
                    transport_protocol_len: int = 8,
                    transport_protocol_type: int = 17,
                    ttl: int = 64,
                    identification: Union[None, int] = None,
                    exit_on_failure: bool = False,
                    exit_code: int = 50,
                    quiet: bool = False) -> Union[None, bytes]:
        """
        Make IPv4 packet header
        :param source_ip: Source IPv4 address string (example: '192.168.1.1')
        :param destination_ip: Destination IPv4 address string (example: '192.168.1.1')
        :param data_len: Length of data integer (example: 0)
        :param transport_protocol_len: Length of transport protocol header integer (example: 8)
        :param transport_protocol_type: Transport protocol type integer (example: 17 - UDP)
        :param ttl: Time to live (default: 64)
        :param identification: Identification integer or None (default: None)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 50)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        error_text: str = 'Failed to make IPv4 header!'
        ip_header: bytes = b''
        try:
            # Source IPv4
            source_ip: bytes = inet_aton(source_ip)

            # Destination IPv4
            destination_ip: bytes = inet_aton(destination_ip)

            # Differentiated Services Code Point and Explicit Congestion Notification
            dscp_ecn: int = 0

            # Packet length
            total_len = data_len + transport_protocol_len + self.header_length

            # Identification
            if identification is None:
                ident = htons(randint(1, 65535))
            else:
                assert 1 <= identification <= 65535, \
                    ' Bad identifation integer: ' + self.base.error_text(str(identification)) + \
                    ' identification must be in range: ' + self.base.info_text('1 - 65535')
                ident = htons(identification)

            # Flags and fragmentation offset
            flg_frgoff = 0

            ip_header += pack('!B', (self.version << 4) + int(self.header_length / 4))
            ip_header += pack('!B', dscp_ecn)
            ip_header += pack('!H', total_len)
            ip_header += pack('!H', ident)
            ip_header += pack('!H', flg_frgoff)
            ip_header += pack('!B', ttl)
            ip_header += pack('!B', transport_protocol_type)
            ip_header += pack('!H', 0)  # Check sum
            ip_header += pack('4s', source_ip)
            ip_header += pack('4s', destination_ip)
            checksum = self._checksum(ip_header)
            return pack('!' '2B' '3H' '2B' 'H' '4s' '4s',
                        (self.version << 4) + int(self.header_length / 4), dscp_ecn, total_len,
                        ident, flg_frgoff, ttl, transport_protocol_type, checksum, source_ip, destination_ip)

        except AssertionError as Error:
            error_text += Error.args[0]

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'total_len' in traceback_text:
                error_text += ' Bad data length: ' + self.base.error_text(str(data_len)) + \
                              ' or transport protocol length: ' + self.base.error_text(str(transport_protocol_len))
            if 'transport_protocol_type' in traceback_text:
                error_text += ' Bad data transport protocol type: ' + \
                              self.base.error_text(str(transport_protocol_type)) + \
                              ' acceptable transport protocol type: ' + \
                              self.base.info_text('17 - UDP')
            if 'ttl' in traceback_text:
                error_text += ' Bad ttl: ' + self.base.error_text(str(ttl)) + \
                              ' default ttl: ' + self.base.error_text('64')

        except OSError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'source_ip' in traceback_text:
                error_text += ' Bad source IPv4: ' + self.base.error_text(str(source_ip)) + \
                              ' example IPv4 address: ' + self.base.info_text('192.168.1.1')
            if 'destination_ip' in traceback_text:
                error_text += ' Bad destination IPv4: ' + self.base.error_text(str(destination_ip)) + \
                              ' example IPv4 address: ' + self.base.info_text('192.168.1.1')

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

# endregion


# region Raw IPv6
class RawIPv6:
    """
    Class for making and parsing IPv6 header
    """
    #           0 - 3     4 - 11                     12 - 31
    #         +-------+--------------+----------------------------------------+
    #    0-31 |Version|Traffic Class |              Flow Label                |
    #         +-------+--------------+-------------------+--------------------+
    #   32-63 |Payload Length (32-47)|Next Header (48-55)|  Hop Limit (56-63) |
    #         +----------------------+-------------------+--------------------+
    #  64-191 |                       Source Address                          |
    #         +---------------------------------------------------------------+
    # 192-288 |                    Destination Address                        |
    #         +---------------------------------------------------------------+

    # region Properties

    # Set Header type
    header_type: int = 34525

    # Set Header minimal length
    header_length: int = 40

    # Set Internet protocol version
    version: int = 6

    # Init Raw-packet Base class
    base: Base = Base()

    # endregion

    def make_random_ip(self,
                       octets: int = 1,
                       prefix: Union[None, str] = None,
                       exit_on_failure: bool = True,
                       exit_code: int = 51,
                       quiet: bool = False) -> Union[None, str]:
        """
        Get random IPv6 address string
        :param octets: Number of octets (default: 1)
        :param prefix: IPv6 prefix (default: 'fd00::')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 51)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Random IPv6 address string or None if error
        """
        error_text: str = 'Failed to make random IPv6 address!'
        if prefix is None:
            prefix: str = 'fd00::'
        try:
            inet_pton(AF_INET6, prefix + '1')
        except OSError:
            error_text += ' Bad prefix: ' + self.base.error_text(str(prefix)) + \
                          ' example prefix: ' + self.base.info_text('fd00::')
            prefix: None = None
        try:
            for index in range(0, octets):
                prefix += str(hex(randint(1, 65535))[2:]) + ':'

            prefix: str = prefix[:-1]
            inet_pton(AF_INET6, prefix)
            return prefix

        except TypeError:
            pass

        except OSError:
            error_text += ' Bad number of octets: ' + self.base.error_text(str(octets)) + \
                          ' example: ' + self.base.info_text('1')

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def pack_addr(self,
                  ipv6_address: str = '::',
                  exit_on_failure: bool = True,
                  exit_code: int = 52,
                  quiet: bool = False) -> Union[None, bytes]:
        """
        Pack IPv6 address string to bytes
        :param ipv6_address: IPv6 address string (default: '::')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 52)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: IPv6 address bytes
        """
        try:
            if ipv6_address == '::':
                return b''.join(pack('B', 0) for _ in range(16))
            else:
                return inet_pton(AF_INET6, ipv6_address)
        except OSError:
            error_text = 'Failed to pack IPv6 address: ' + self.base.error_text(str(ipv6_address))

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def parse_header(self,
                     packet: bytes,
                     exit_on_failure: bool = False,
                     exit_code: int = 53,
                     quiet: bool = True) -> Union[None, Dict[str, Union[int, str]]]:
        """
        Parse IPv6 header
        :param packet: Bytes of packet
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 53)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Parsed IPv6 header dictionary (example: {'version': 6, 'traffic-class': 0, 'flow-label': 0, 'payload-length': 8, 'next-header': 17, 'hop-limit': 64, 'source-ip': 'fd00::1', 'destination-ip': 'fd00::2'}) or None if error
        """
        error_text: str = 'Failed to parse IPv6 header!'
        try:
            assert not len(packet) < self.header_length, \
                ' Bad packet length: ' + self.base.error_text(str(len(packet))) + \
                ' minimal IPv6 header length: ' + self.base.info_text(str(self.header_length))

            version_class_and_label = int(unpack('!L', packet[0:4])[0])
            version = int(int(version_class_and_label & 0b11110000000000000000000000000000) >> 28)
            traffic_class = int(int(version_class_and_label & 0b00001111111100000000000000000000) >> 20)
            flow_label = int(version_class_and_label & 0b00000000000011111111111111111111)

            assert version == self.version, ' Bad IP version: ' + self.base.error_text(str(version)) + \
                                            ' default IP version: ' + self.base.info_text(str(self.version))

            ipv6_detailed = unpack('!' 'H' '2B' '16s' '16s', packet[4:self.header_length])

            return {
                'version':        version,
                'traffic-class':  traffic_class,
                'flow-label':     flow_label,
                'payload-length': int(ipv6_detailed[0]),
                'next-header':    int(ipv6_detailed[1]),
                'hop-limit':      int(ipv6_detailed[2]),
                'source-ip':      inet_ntop(AF_INET6, ipv6_detailed[3]),
                'destination-ip': inet_ntop(AF_INET6, ipv6_detailed[4])
            }

        except AssertionError as Error:
            error_text += Error.args[0]

        except IndexError:
            pass

        except sock_error:
            pass

        except struct_error:
            pass

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_header(self,
                    source_ip: str = 'fd00::1',
                    destination_ip: str = 'fd00::2',
                    traffic_class: int = 0,
                    flow_label: int = 0,
                    payload_len: int = 8,
                    next_header: int = 17,
                    hop_limit: int = 64,
                    exit_on_failure: bool = False,
                    exit_code: int = 54,
                    quiet: bool = False) -> Union[None, bytes]:
        """
        Make IPv6 packet header
        :param source_ip: Source IPv6 address string (example: 'fd00::1')
        :param destination_ip: Destination IPv6 address string (example: 'fd00::2')
        :param traffic_class: Differentiated Services Code Point and Explicit Congestion Notification (default: 0)
        :param flow_label: Flow label integer (default: 0)
        :param payload_len: Length of payload integer (example: 8)
        :param next_header: Next transport protocol header type integer (example: 17 - UDP)
        :param hop_limit: Hop limit integer (default: 64)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 54)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        error_text: str = 'Failed to make IPv6 header!'
        header: bytes = b''
        try:
            # Assertions
            assert traffic_class.bit_length() <= 7, \
                ' Bad traffic class: ' + self.base.error_text(str(traffic_class)) + \
                ' default traffic class: ' + self.base.info_text('0')
            assert flow_label.bit_length() <= 20, \
                ' Bad flow label: ' + self.base.error_text(str(flow_label)) + \
                ' default flow label: ' + self.base.info_text('0')
            assert payload_len.bit_length() <= 16, \
                ' Bad payload length: ' + self.base.error_text(str(payload_len)) + \
                ' default payload length: ' + self.base.info_text('8')
            assert next_header.bit_length() <= 8, \
                ' Bad next header: ' + self.base.error_text(str(next_header)) + \
                ' default next header: ' + self.base.info_text('17')
            assert hop_limit.bit_length() <= 8, \
                ' Bad hop limit: ' + self.base.error_text(str(hop_limit)) + \
                ' default hop limit: ' + self.base.info_text('64')

            # Source IPv6 address
            source_ipv6: Union[None, str] = self.pack_addr(ipv6_address=source_ip,
                                                           exit_on_failure=exit_on_failure,
                                                           exit_code=exit_code,
                                                           quiet=quiet)

            # Destination IPv6 address
            destination_ipv6: Union[None, str] = self.pack_addr(ipv6_address=destination_ip,
                                                                exit_on_failure=exit_on_failure,
                                                                exit_code=exit_code,
                                                                quiet=quiet)

            # Pack header
            header += pack('!I', (self.version << 28) + (traffic_class << 20) + flow_label)
            header += pack('!I', (payload_len << 16) + (next_header << 8) + hop_limit)
            header += source_ipv6
            header += destination_ipv6
            return header

        except AssertionError as Error:
            error_text += Error.args[0]

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'traffic_class' in traceback_text:
                error_text += ' Bad traffic class: ' + self.base.error_text(str(traffic_class)) + \
                              ' or flow label: ' + self.base.error_text(str(flow_label))
            if 'payload_len' in traceback_text:
                error_text += ' Bad payload length: ' + self.base.error_text(str(payload_len)) + \
                              ' or next header: ' + self.base.error_text(str(next_header)) + \
                              ' or hop limit: ' + self.base.error_text(str(hop_limit))

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'source_ipv6' in traceback_text:
                error_text += ' Bad source IPv6 address: ' + self.base.error_text(str(source_ip)) + \
                              ' example IPv6 address: ' + self.base.info_text('fd00::1')
            if 'destination_ipv6' in traceback_text:
                error_text += ' Bad destination IPv6 address: ' + self.base.error_text(str(destination_ip)) + \
                              ' example IPv6 address: ' + self.base.info_text('fd00::1')

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

# endregion


# region Raw UDP
class RawUDP:
    """
    Class for making and parsing UDP header
    """
    #  0                16               31
    #  +-----------------+-----------------+
    #  |     Source      |   Destination   |
    #  |      Port       |      Port       |
    #  +-----------------+-----------------+
    #  |                 |                 |
    #  |     Length      |    Checksum     |
    #  +-----------------+-----------------+
    #  |
    #  |          data octets ...
    #  +---------------- ...

    # region Properties

    # Set Header type
    header_type: int = 17

    # Set Header minimal length
    header_length: int = 8

    # Init Raw IPv6
    ipv6: RawIPv6 = RawIPv6()

    # Init Raw-packet Base class
    base: Base = Base()

    # endregion

    @staticmethod
    def _checksum(packet: bytes) -> int:
        """
        Calculate packet checksum
        :param packet: Bytes of packet
        :return: Result checksum
        """
        if len(packet) % 2 == 1:
            packet += b'\x00'
        s = sum(array('H', packet))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s >> 8) & 0xff) | s << 8) & 0xffff

    def parse_header(self,
                     packet: bytes,
                     exit_on_failure: bool = False,
                     exit_code: int = 55,
                     quiet: bool = True) -> Union[None, Dict[str, Union[int, str]]]:
        """
        Parse UDP header
        :param packet: Bytes of packet
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 55)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Parsed UDP header dictionary (example: {'source-port': 5353, 'destination-port': 5353, 'length': 8, 'checksum': 56327}) or None if error
        """
        error_text: str = 'Failed to parse UDP header!'
        try:
            assert not len(packet) < self.header_length, \
                ' Bad packet length: ' + self.base.error_text(str(len(packet))) + \
                ' minimal UDP header length: ' + self.base.info_text(str(self.header_length))

            udp_detailed = unpack('!4H', packet[:self.header_length])

            return {
                'source-port':      int(udp_detailed[0]),
                'destination-port': int(udp_detailed[1]),
                'length':           int(udp_detailed[2]),
                'checksum':         int(udp_detailed[3]),
            }

        except AssertionError as Error:
            error_text += Error.args[0]

        except IndexError:
            pass

        except struct_error:
            pass

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_header(self,
                    source_port: int = 5353,
                    destination_port: int = 5353,
                    data_length: int = 0,
                    exit_on_failure: bool = False,
                    exit_code: int = 56,
                    quiet: bool = False) -> Union[None, bytes]:
        """
        Make UDP header
        :param source_port: Source UDP port integer (example: 5353)
        :param destination_port: Destination UDP port integer (example: 5353)
        :param data_length: Length of payload integer (example: 0)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 56)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of header
        """
        error_text: str = 'Failed to make UDP header!'
        header: bytes = b''
        try:
            header += pack('!H', source_port)
            header += pack('!H', destination_port)
            header += pack('!H', data_length + 8)
            header += pack('!H', 0)     # Check sum
            return header

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'source_port' in traceback_text:
                error_text += ' Bad source port: ' + self.base.error_text(str(source_port)) + \
                              ' source port must be in range: ' + self.base.info_text('1 - 65535')
            if 'destination_port' in traceback_text:
                error_text += ' Bad destination port: ' + self.base.error_text(str(destination_port)) + \
                              ' destination port must be in range: ' + self.base.info_text('1 - 65535')
            if 'data_length' in traceback_text:
                error_text += ' Bad data length: ' + self.base.error_text(str(data_length)) + \
                              ' data length must be in range: ' + self.base.info_text('1 - 65527')

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_header_with_ipv6_checksum(self,
                                       ipv6_src: str = 'fd00::1',
                                       ipv6_dst: str = 'fd00::2',
                                       port_src: int = 5353,
                                       port_dst: int = 5353,
                                       payload_len: int = 0,
                                       payload_data: bytes = b'',
                                       exit_on_failure: bool = False,
                                       exit_code: int = 57,
                                       quiet: bool = False) -> Union[None, bytes]:
        """
        Make UDP header with checksum for 6 version Internet protocol
        :param ipv6_src: Source IPv6 address string (example: 'fd00::1')
        :param ipv6_dst: Destination IPv6 address string (example: 'fd00::1')
        :param port_src: Source UDP port integer (example: 5353)
        :param port_dst: Destination UDP port integer (example: 5353)
        :param payload_len: Length of payload integer (example: 0)
        :param payload_data: Payload data (example: b'')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 57)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of header
        """
        error_text = 'Failed to make UDP header!'
        psh: bytes = b''
        header: bytes = b''
        try:
            # Calculate data length
            data_length: int = payload_len + self.header_length

            # Make begin of header
            header += pack('!H', port_src)
            header += pack('!H', port_dst)
            header += pack('!H', data_length)

            # Make placeholder
            psh += self.ipv6.pack_addr(exit_on_failure=exit_on_failure, exit_code=exit_code,
                                       quiet=quiet, ipv6_address=ipv6_src)
            psh += self.ipv6.pack_addr(exit_on_failure=exit_on_failure, exit_code=exit_code,
                                       quiet=quiet, ipv6_address=ipv6_dst)
            psh += pack('!2B', 0, self.header_type)
            psh += pack('!H', data_length)

            # Make udp header without check sum
            udp_header: Union[None, bytes] = self.make_header(source_port=port_src,
                                                              destination_port=port_dst,
                                                              data_length=payload_len,
                                                              exit_on_failure=exit_on_failure,
                                                              exit_code=exit_code,
                                                              quiet=quiet)

            # Calculate check sum
            checksum: int = self._checksum(psh + udp_header + payload_data)

            # Add check sum to header
            header += pack('!H', checksum)
            return header

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'port_src' in traceback_text:
                error_text += ' Bad source port: ' + self.base.error_text(str(port_src)) + \
                              ' source port must be in range: ' + self.base.info_text('1 - 65535')
            if 'port_dst' in traceback_text:
                error_text += ' Bad destination port: ' + self.base.error_text(str(port_dst)) + \
                              ' destination port must be in range: ' + self.base.info_text('1 - 65535')
            if 'data_length' in traceback_text:
                error_text += ' Bad data length: ' + self.base.error_text(str(payload_len)) + \
                              ' data length must be in range: ' + self.base.info_text('1 - 65527')

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'ipv6_src' in traceback_text:
                error_text += ' Bad source IPv6 address: ' + self.base.error_text(str(ipv6_src)) + \
                              ' example IPv6 address: ' + self.base.info_text('fd00::1')
            if 'ipv6_dst' in traceback_text:
                error_text += ' Bad destination IPv6 address: ' + self.base.error_text(str(ipv6_dst)) + \
                              ' example IPv6 address: ' + self.base.info_text('fd00::1')

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_header_with_ipv4_checksum(self,
                                       ipv4_src: str = '192.168.0.2',
                                       ipv4_dst: str = '192.168.0.1',
                                       port_src: int = 5353,
                                       port_dst: int = 5353,
                                       payload_len: int = 0,
                                       payload_data: bytes = b'',
                                       exit_on_failure: bool = False,
                                       exit_code: int = 57,
                                       quiet: bool = False) -> Union[None, bytes]:
        """
        Make UDP header with checksum for 4 version Internet protocol
        :param ipv4_src: Source IPv4 address string (example: '192.168.0.2')
        :param ipv4_dst: Destination IPv4 address string (example: '192.168.0.1')
        :param port_src: Source UDP port integer (example: 5353)
        :param port_dst: Destination UDP port integer (example: 5353)
        :param payload_len: Length of payload integer (example: 0)
        :param payload_data: Payload data (example: b'')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 57)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of header
        """
        error_text = 'Failed to make UDP header!'
        psh: bytes = b''
        header: bytes = b''
        try:
            # Calculate data length
            data_length: int = payload_len + self.header_length

            # Make begin of header
            header += pack('!H', port_src)
            header += pack('!H', port_dst)
            header += pack('!H', data_length)

            # Make placeholder
            psh += inet_aton(ipv4_src)
            psh += inet_aton(ipv4_dst)
            psh += pack('!2B', 0, self.header_type)
            psh += pack('!H', data_length)

            # Make udp header without check sum
            udp_header: Union[None, bytes] = self.make_header(source_port=port_src,
                                                              destination_port=port_dst,
                                                              data_length=payload_len,
                                                              exit_on_failure=exit_on_failure,
                                                              exit_code=exit_code,
                                                              quiet=quiet)

            # Calculate check sum
            checksum: int = self._checksum(psh + udp_header + payload_data)

            # Add check sum to header
            header += pack('!H', checksum)
            return header

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'port_src' in traceback_text:
                error_text += ' Bad source port: ' + self.base.error_text(str(port_src)) + \
                              ' source port must be in range: ' + self.base.info_text('1 - 65535')
            if 'port_dst' in traceback_text:
                error_text += ' Bad destination port: ' + self.base.error_text(str(port_dst)) + \
                              ' destination port must be in range: ' + self.base.info_text('1 - 65535')
            if 'data_length' in traceback_text:
                error_text += ' Bad data length: ' + self.base.error_text(str(payload_len)) + \
                              ' data length must be in range: ' + self.base.info_text('1 - 65527')

        except OSError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'ipv4_src' in traceback_text:
                error_text += ' Bad source IPv4 address: ' + self.base.error_text(str(ipv4_src)) + \
                              ' example IPv4 address: ' + self.base.info_text('192.168.0.2')
            if 'ipv4_dst' in traceback_text:
                error_text += ' Bad destination IPv4 address: ' + self.base.error_text(str(ipv4_dst)) + \
                              ' example IPv4 address: ' + self.base.info_text('192.168.0.1')

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

# endregion


# region Raw TCP
class RawTCP:
    """
    Class for making and parsing TCP header
    """

    timestamp_value = 0

    def __init__(self):
        with open('/proc/uptime', 'r') as uptime:
            self.timestamp_value = int(float(uptime.readline().split()[0]))

    def update_timestamp(self):
        with open('/proc/uptime', 'r') as uptime:
            self.timestamp_value = int(float(uptime.readline().split()[0]))

    @staticmethod
    def checksum(msg):
        s = 0
        if len(msg) % 2 == 1:
            msg += '\0'
        for i in range(0, len(msg), 2):
            w = (ord(msg[i]) << 8) + (ord(msg[i + 1]))
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def make_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, flag, win, opt_exist=False, opt=None, data=''):

        reserved = 0
        window = win
        chksum = 0
        urg = 0

        if opt_exist:
            opt_len = len(opt) / 4
            offset = 5 + opt_len
        else:
            offset = 5

        tcp_header = pack('!' '2H' '2L' '2B' '3H',
                          port_src, port_dst, seq, ack, (offset << 4) + reserved, flag, window, chksum, urg)

        if opt_exist:
            tcp_header += opt

        source_address = inet_aton(ip_src)
        destination_address = inet_aton(ip_dst)
        placeholder = 0
        protocol = IPPROTO_TCP
        tcp_length = len(tcp_header) + len(data)
        psh = pack('!' '4s' '4s' '2B' 'H', source_address, destination_address, placeholder, protocol, tcp_length)

        chksum = self.checksum(psh + tcp_header + data)

        tcp_header = pack('!' '2H' '2L' '2B' '3H',
                          port_src, port_dst, seq, ack, (offset << 4) + reserved, flag, window, chksum, urg)

        if opt_exist:
            return tcp_header + opt
        else:
            return tcp_header

    def make_syn_header(self, ip_src, ip_dst, port_src, port_dst, seq):
        option_mss = pack('!2B H', 2, 4, 1460)
        option_sack = pack('!2B', 4, 2)
        self.update_timestamp()
        option_timestamp = pack('! 2B 2L', 8, 10, self.timestamp_value, 0)
        option_nop = pack('!B', 1)
        option_scale = pack('!3B', 3, 3, 7)
        options = option_mss + option_sack + option_timestamp + option_nop + option_scale

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, 0, 2, 29200, True, options)

    def make_ack_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, tsecr=-1):
        option_nop = pack('!B', 1)
        if tsecr != -1:
            self.update_timestamp()
            option_timestamp = pack('! 2B 2L', 8, 10, self.timestamp_value, tsecr)
            options = option_nop + option_nop + option_timestamp
        else:
            options = option_nop + option_nop

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, ack, 16, 29200, True, options)

    def make_psh_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, tsecr=-1, data=''):
        option_nop = pack('!B', 1)
        if tsecr != -1:
            self.update_timestamp()
            option_timestamp = pack('! 2B 2L', 8, 10, self.timestamp_value, tsecr)
            options = option_nop + option_nop + option_timestamp
        else:
            options = option_nop + option_nop

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, ack, 24, 29200, False, options, data)

    def make_fin_header(self, ip_src, ip_dst, port_src, port_dst, seq, ack, tsecr=-1):
        option_nop = pack('!B', 1)
        if tsecr != -1:
            self.update_timestamp()
            option_timestamp = pack('! 2B 2L', 8, 10, self.timestamp_value, tsecr)
            options = option_nop + option_nop + option_timestamp
        else:
            options = option_nop + option_nop

        return self.make_header(ip_src, ip_dst, port_src, port_dst, seq, ack, 17, 29200, False, options)
# endregion


# region Raw DNS
class RawDNS:
    """
    Class for making and parsing DNS packets
    """
    #  0                 16                 31
    #  +------------------+------------------+
    #  |  Transaction ID  |      Flags       |
    #  +------------------+------------------+
    #  |    Questions     |    Answer RRS    |
    #  +------------------+------------------+
    #  |  Authority RRs   |  Additional RRs  |
    #  +------------------+------------------+
    #  |          Queries ...
    #  +---------------- ...

    # region Properties

    # Set minimal DNS packet length
    packet_length: int = 12

    # Init Raw Ethernet
    eth: RawEthernet = RawEthernet()

    # Init Raw IPv4
    ipv4: RawIPv4 = RawIPv4()

    # Init Raw IPv6
    ipv6: RawIPv6 = RawIPv6()

    # Init Raw DNS
    udp: RawUDP = RawUDP()

    # Init Raw-packet Base class
    base: Base = Base()

    # endregion

    @staticmethod
    def get_top_level_domain(name: str = 'www.test.com') -> str:
        try:
            position: int = name.find('.')
            assert not position == -1, 'Could not find "." in domain name!'
            return name[position + 1:]
        except AssertionError:
            return name

    def pack_dns_name(self,
                      name: str = 'test.com',
                      exit_on_failure: bool = False,
                      exit_code: int = 65,
                      quiet: bool = False) -> Union[None, bytes]:
        """
        Convert DNS name to bytes
        :param name: Domain name string (example: 'test.com')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 65)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of domain name (example: b'\x04test\x03com\x00') or None if error
        """

        # region Variables
        name_list: List[str] = str(name).split('.')
        result_name: bytes = b''
        # endregion

        try:
            for part_of_name in name_list:
                result_name += pack('!' 'B' '%ds' % (len(part_of_name)), len(part_of_name),
                                    part_of_name.encode('utf-8'))
        except struct_error:
            if not quiet:
                self.base.print_error('Failed to pack domain name string: ', str(name))
            if exit_on_failure:
                exit(exit_code)
            else:
                return None

        return result_name + b'\x00'

    def unpack_dns_name(self,
                        packed_name: bytes = b'\x04mail\xc0\x11',
                        name: str = 'test.com',
                        exit_on_failure: bool = False,
                        exit_code: int = 66,
                        quiet: bool = False) -> Union[None, str]:
        """
        Under construction
        :param packed_name: Bytes of packed name (example: b'\x04mail\xc0\x11')
        :param name: Domain name string (example: 'test.com')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 66)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Domain name string (example: 'mail.test.com') or None if error
        """
        
        # region Variables
        result_name: str = ''
        position: int = 0
        # endregion

        try:
            name_length = int(unpack('B', packed_name[0:1])[0])

            while name_length != 0:
                if packed_name[position:position + 2] == b'\xc0\x11':
                    return result_name + self.get_top_level_domain(name)
                elif packed_name[position:position + 2] == b'\xc0\x10':
                    return name
                elif packed_name[position:position + 2] == b'\xc0\x0c':
                    return result_name + name
                else:
                    result_name += packed_name[position + 1:position + name_length + 1].decode('utf-8') + '.'
                    position += name_length + 1
                    name_length = int(unpack('!B', packed_name[position:position + 1])[0])

            return result_name

        except struct_error:
            pass

        except UnicodeDecodeError:
            pass

        if not quiet:
            self.base.print_error('Failed to unpack domain name bytes: ', str(name))
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def parse_packet(self,
                     packet: bytes,
                     exit_on_failure: bool = False,
                     exit_code: int = 67,
                     quiet: bool = True) -> Union[None, Dict[str, Union[int, str, Dict[str, Union[int, str]]]]]:
        """
        Parse DNS Packet
        :param packet: Bytes of network packet
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 67)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Parsed DNS packet dictionary (example: {'transaction-id': 1, 'flags': 0, 'questions': 1, 'answer-rrs': 1, 'authority-rrs': 0, 'additional-rrs': 0, 'queries': [{'name': 'test.com.', 'type': 1, 'class': 1}], 'answers': [{'name': 'test.com.', 'type': 1, 'class': 1, 'ttl': 65535, 'address': '192.168.1.1'}]}) or None if error
        """
        error_text: str = 'Failed to parse DNS packet!'
        try:
            # Init lists for DNS queries and answers
            queries: List[Dict[str, Union[int, str]]] = list()
            answers: List[Dict[str, Union[int, str]]] = list()

            # Check length of packet
            assert not len(packet) < self.packet_length, \
                ' Bad packet length: ' + self.base.error_text(str(len(packet))) + \
                ' minimal DNS packet length: ' + self.base.info_text(str(self.packet_length))

            # region Parse DNS packet header

            # Transaction ID: 2 bytes
            # Flags: 2 bytes
            # Questions: 2 bytes
            # Answer RRS: 2 bytes
            # Authority RRs: 2 bytes
            # Additional RRs: 2 bytes
            dns_detailed = unpack('!6H', packet[:self.packet_length])

            dns_packet = {
                'transaction-id': int(dns_detailed[0]),
                'flags':          int(dns_detailed[1]),
                'questions':      int(dns_detailed[2]),
                'answer-rrs':     int(dns_detailed[3]),
                'authority-rrs':  int(dns_detailed[4]),
                'additional-rrs': int(dns_detailed[5]),
            }

            if dns_packet['transaction-id'] == 0:
                return None
            # endregion

            # region Parse DNS queries and answers
            if len(packet) > self.packet_length:

                number_of_queries = 0
                number_of_answers = 0
                position = self.packet_length

                # region Parse DNS queries
                while number_of_queries < dns_packet['questions']:

                    query_name = ''
                    query_name_length = int(unpack('B', packet[position:position + 1])[0])

                    while query_name_length != 0:
                        query_name += packet[position + 1:position + query_name_length + 1].decode('utf-8') + '.'
                        position += query_name_length + 1
                        query_name_length = int(unpack('B', packet[position:position + 1])[0])

                    query_type = int(unpack('!H', packet[position + 1:position + 3])[0])
                    query_class = int(unpack('!H', packet[position + 3:position + 5])[0])
                    position += 5

                    queries.append({
                        'name':  query_name,
                        'type':  query_type,
                        'class': query_class
                    })

                    number_of_queries += 1

                dns_packet['queries'] = queries
                # endregion

                # region Parse DNS answers
                if dns_packet['flags'] == 0x8180 or dns_packet['flags'] == 0x8080:
                    cname: str = ''
                    while number_of_answers < dns_packet['answer-rrs']:

                        answer_name: str = ''
                        if packet[position:position + 2] == b'\xc0\x0c':
                            answer_name = dns_packet['queries'][0]['name']
                            position += 2

                        elif packet[position:position + 2] == b'\xc0\x2d':
                            answer_name = cname
                            position += 2

                        else:
                            answer_name_length = int(unpack('B', packet[position:position + 1])[0])
                            while answer_name_length != 0:
                                answer_name += packet[position + 1:position + answer_name_length + 1].decode('utf-8') + '.'
                                position += answer_name_length + 1
                                answer_name_length = int(unpack('B', packet[position:position + 1])[0])
                            position += 1

                        answer_type = int(unpack('!H', packet[position:position + 2])[0])
                        answer_class = int(unpack('!H', packet[position + 2:position + 4])[0])
                        answer_ttl = int(unpack('!I', packet[position + 4:position + 8])[0])
                        answer_data_len = int(unpack('!H', packet[position + 8:position + 10])[0])
                        position += 10

                        answer_address: str = ''

                        # Answer type: 1 - Type A (IPv4 address)
                        if answer_type == 1:
                            answer_address = inet_ntoa(packet[position:position + answer_data_len])

                        # Answer type: 28 - Type AAAA (IPv6 address)
                        if answer_type == 28:
                            answer_address = inet_ntop(AF_INET6, packet[position:position + answer_data_len])

                        # Answer type: 5 - Type CNAME (Canonicial NAME for an alias)
                        if answer_type == 5:
                            answer_address = self.unpack_dns_name(packed_name=packet[position:position+answer_data_len],
                                                                  name=answer_name,
                                                                  exit_on_failure=exit_on_failure,
                                                                  exit_code=exit_code,
                                                                  quiet=quiet)
                            cname = answer_address

                        if answer_type == 2:
                            answer_address = self.unpack_dns_name(packed_name=packet[position:position+answer_data_len],
                                                                  name=answer_name,
                                                                  exit_on_failure=exit_on_failure,
                                                                  exit_code=exit_code,
                                                                  quiet=quiet)

                        position += answer_data_len

                        answers.append({
                            'name': answer_name,
                            'type': answer_type,
                            'class': answer_class,
                            'ttl': answer_ttl,
                            'address': answer_address
                        })

                        number_of_answers += 1

                    dns_packet['answers'] = answers
                # endregion

            # endregion

            # Return parsed packet: dictionary
            return dns_packet

        except AssertionError as Error:
            error_text += Error.args[0]

        except UnicodeDecodeError:
            pass

        except struct_error:
            pass

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_response_packet(self,
                             ethernet_src_mac: str = '01:23:45:67:89:0a',
                             ethernet_dst_mac: str = '01:23:45:67:89:0b',
                             ip_src: str = '192.168.1.1',
                             ip_dst: str = '192.168.1.2',
                             ip_ident: Union[None, int] = None,
                             ip_ttl: int = 64,
                             udp_src_port: int = 53,
                             udp_dst_port: int = 5353,
                             transaction_id: int = 1,
                             flags: int = 0x8180,   # Standart DNS response, No error
                             queries: List[Dict[str, Union[int, str]]] =
                             [{'type': 1, 'class': 1, 'name': 'test.com'}],
                             answers_address: List[Dict[str, Union[int, str]]] =
                             [{'name': 'test.com', 'type': 1, 'class': 1, 'ttl': 65535, 'address': '192.168.1.1'}],
                             name_servers={},
                             exit_on_failure: bool = False,
                             exit_code: int = 68,
                             quiet: bool = False) -> Union[None, bytes]:
        """
        Make DNS response packet
        :type queries: object
        :type answers_address: object
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ip_src: Source IPv4 or IPv6 address string in Network header (example: '192.168.1.1')
        :param ip_dst: Destination IPv4 or IPv6 address string in Network header (example: '192.168.1.2')
        :param ip_ttl: TTL for IPv4 header or hop limit for IPv6 header (default: 64)
        :param ip_ident: Identification integer value for IPv4 header (optional value)
        :param udp_src_port: Source UDP port (default: 53)
        :param udp_dst_port: Source UDP port (example: 5353)
        :param transaction_id: DNS transaction id integer (example: 1)
        :param flags: DNS flags (default: 0)
        :param queries: List with DNS queries (example: [{'type': 1, 'class': 1, 'name': 'test.com'}])
        :param answers_address: List with DNS answers address (example: [{'name': 'test.com', 'type': 1, 'class': 1, 'ttl': 65535, 'address': '192.168.1.1'}])
        :param name_servers: Dictionary with name servers (Under constraction)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 68)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        error_text: str = 'Failed to make DNS response packet!'
        packet: bytes = b''
        mail_server_preference: int = 10
        try:
            dns_packet: bytes = b''
            dns_packet += pack('!H', transaction_id)            # DNS transaction ID
            dns_packet += pack('!H', flags)                     # DNS flags
            dns_packet += pack('!H', len(queries))              # Questions
            dns_packet += pack('!H', len(answers_address))      # Answer RRs
            dns_packet += pack('!H', len(name_servers.keys()))  # Authority RRs
            dns_packet += pack('!H', len(name_servers.keys()))  # Additionsl RRS

            query_name: str = ''
            for query in queries:
                query_name = query['name']

                if query_name.endswith('.'):
                    query_name = query_name[:-1]

                dns_packet += self.pack_dns_name(query_name)
                dns_packet += pack('!H', query['type'])
                dns_packet += pack('!H', query['class'])

            for address in answers_address:
                if 'name' in address.keys():
                    if len(queries) == 1 and query_name == address['name']:
                        dns_packet += pack('!H', 0xc00c)
                    else:
                        dns_packet += self.pack_dns_name(address['name'])
                else:
                    dns_packet += pack('!H', 0xc00c)

                dns_packet += pack('!H', address['type'])   # Type: 1 - A, 28 - AAAA
                dns_packet += pack('!H', address['class'])  # Class: 1 - IN
                dns_packet += pack('!I', address['ttl'])    # Address ttl

                if int(address['type']) == 1:
                    dns_packet += pack('!H', 4)                               # IPv4 address length
                    dns_packet += pack('!4s', inet_aton(address['address']))  # IPv4 address

                elif int(address['type']) == 28:
                    dns_packet += pack('!H', 16)                                         # IPv6 address length
                    dns_packet += pack('!16s', inet_pton(AF_INET6, address['address']))  # IPv6 address

                elif int(address['type']) == 2 or int(address['type']) == 12:
                    domain: bytes = self.pack_dns_name(address['address'])  # Domain name
                    dns_packet += pack('!H', len(domain))  # Domain length
                    dns_packet += domain

                elif int(address['type']) == 15:
                    domain: bytes = self.pack_dns_name(address['address'])  # Domain name
                    dns_packet += pack('!H', len(domain) + 2)  # Domain length
                    dns_packet += pack('!H', mail_server_preference)  # Mail server preference
                    dns_packet += domain
                    mail_server_preference += 10

                # elif int(address['type']) == 15:
                #     domain: str = address['address'].replace(query_name, '')
                #     if domain.endswith('.'):
                #         domain: str = domain[:-1]
                #     domain: bytes = self.pack_dns_name(domain)
                #     domain: bytes = domain[:-1] + b'\xc0\x0c'
                #     dns_packet += pack('!H', len(domain) + 2)
                #     dns_packet += pack('!H', mail_server_preference)
                #     dns_packet += domain
                #     mail_server_preference += 10

            # region IPv4 request
            if self.base.ip_address_validation(ip_address=ip_src, exit_on_failure=False, quiet=True):

                packet += self.eth.make_header(network_type=self.ipv4.header_type,
                                               exit_on_failure=exit_on_failure,
                                               exit_code=exit_code,
                                               quiet=quiet,
                                               source_mac=ethernet_src_mac,
                                               destination_mac=ethernet_dst_mac)

                packet += self.ipv4.make_header(data_len=len(dns_packet),
                                                transport_protocol_len=self.udp.header_length,
                                                transport_protocol_type=self.udp.header_type,
                                                ttl=ip_ttl,
                                                identification=ip_ident,
                                                exit_on_failure=exit_on_failure,
                                                exit_code=exit_code,
                                                quiet=quiet,
                                                source_ip=ip_src,
                                                destination_ip=ip_dst)

                packet += self.udp.make_header_with_ipv4_checksum(ipv4_src=ip_src,
                                                                  ipv4_dst=ip_dst,
                                                                  payload_len=len(dns_packet),
                                                                  payload_data=dns_packet,
                                                                  exit_on_failure=exit_on_failure,
                                                                  exit_code=exit_code,
                                                                  quiet=quiet,
                                                                  port_src=udp_src_port,
                                                                  port_dst=udp_dst_port)
            # endregion

            # region IPv6 request
            elif self.base.ipv6_address_validation(ipv6_address=ip_src, exit_on_failure=False, quiet=True):

                packet += self.eth.make_header(network_type=self.ipv6.header_type,
                                               exit_on_failure=exit_on_failure,
                                               exit_code=exit_code,
                                               quiet=quiet,
                                               source_mac=ethernet_src_mac,
                                               destination_mac=ethernet_dst_mac)

                packet += self.ipv6.make_header(traffic_class=0,
                                                flow_label=0,
                                                payload_len=self.udp.header_length + len(dns_packet),
                                                next_header=self.udp.header_type,
                                                hop_limit=ip_ttl,
                                                exit_on_failure=exit_on_failure,
                                                exit_code=exit_code,
                                                quiet=quiet,
                                                source_ip=ip_src,
                                                destination_ip=ip_dst)

                packet += self.udp.make_header_with_ipv6_checksum(ipv6_src=ip_src,
                                                                  ipv6_dst=ip_dst,
                                                                  payload_len=len(dns_packet),
                                                                  payload_data=dns_packet,
                                                                  exit_on_failure=exit_on_failure,
                                                                  exit_code=exit_code,
                                                                  quiet=quiet,
                                                                  port_src=udp_src_port,
                                                                  port_dst=udp_dst_port)

            # endregion

            # region Unknown network - return None
            else:
                raise TypeError('Unknown network!')
            # endregion

            return packet + dns_packet

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'ethernet_dst_mac' in traceback_text:
                error_text += ' Bad source or destination MAC address!'
            if 'Unknown network' in traceback_text:
                error_text += ' Bad source or destination IP address!'
            if 'udp_dst_port' in traceback_text:
                error_text += ' Bad source or destination UDP port!'

        except OSError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'inet_aton' in traceback_text:
                error_text += ' Bad IPv4 address in answers!'
            if 'inet_pton' in traceback_text:
                error_text += ' Bad IPv6 address in answer!'

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'transaction_id' in traceback_text:
                error_text += ' Bad transaction ID: ' + self.base.error_text(str(transaction_id)) + \
                              ' transaction ID must be in range: ' + self.base.info_text('1 - 65535')
            if 'flags' in traceback_text:
                error_text += ' Bad flags: ' + self.base.error_text(str(flags)) + \
                              ' flags must be in range: ' + self.base.info_text('1 - 65535')
            if 'type' in traceback_text:
                error_text += ' Query type be in range: ' + self.base.info_text('1 - 65535')
            if 'class' in traceback_text:
                error_text += ' Query class must be in range: ' + self.base.info_text('1 - 65535')

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_ipv4_request_packet(self,
                                 ethernet_src_mac: str = '01:23:45:67:89:0a',
                                 ethernet_dst_mac: str = '01:23:45:67:89:0b',
                                 ip_src: str = '192.168.1.1',
                                 ip_dst: str = '192.168.1.2',
                                 ip_ttl: int = 64,
                                 ip_ident: Union[None, int] = None,
                                 udp_src_port: int = 5353,
                                 udp_dst_port: int = 53,
                                 transaction_id: int = 1,
                                 queries: List[Dict[str, Union[int, str]]] =
                                 [{'type': 1, 'class': 1, 'name': 'test.com'}],
                                 flags=0,
                                 exit_on_failure: bool = False,
                                 exit_code: int = 69,
                                 quiet: bool = False) -> Union[None, bytes]:
        """
        Make DNS request packet for IPv4 network
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ip_src: Source IPv4 address string in Network header (example: '192.168.1.1')
        :param ip_dst: Destination IPv4 address string in Network header (example: '192.168.1.2')
        :param ip_ttl: TTL for IPv4 header (default: 64)
        :param ip_ident: Identification integer value for IPv4 header (optional value)
        :param udp_src_port: Source UDP port (example: 5353)
        :param udp_dst_port: Source UDP port (default: 53)
        :param transaction_id: DNS transaction id integer (example: 1)
        :param flags: DNS flags (default: 0)
        :param queries: List with DNS queries (example: [{'type': 1, 'class': 1, 'name': 'test.com'}])
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 69)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        error_text: str = 'Failed to make IPv4 DNS request packet!'
        packet: bytes = b''
        try:
            dns_packet: bytes = b''
            dns_packet += pack('!H', transaction_id)  # DNS transaction ID
            dns_packet += pack('!H', flags)           # DNS flags
            dns_packet += pack('!H', len(queries))    # Questions
            dns_packet += pack('!H', 0)               # Answer RRs
            dns_packet += pack('!H', 0)               # Authority RRs
            dns_packet += pack('!H', 0)               # Additionsl RRS

            for query in queries:
                dns_packet += self.pack_dns_name(query['name'])
                dns_packet += pack('!H', query['type'])
                dns_packet += pack('!H', query['class'])

            packet += self.eth.make_header(network_type=self.ipv4.header_type,
                                           exit_on_failure=exit_on_failure,
                                           exit_code=exit_code,
                                           quiet=quiet,
                                           source_mac=ethernet_src_mac,
                                           destination_mac=ethernet_dst_mac)

            packet += self.ipv4.make_header(data_len=len(dns_packet),
                                            transport_protocol_len=self.udp.header_length,
                                            transport_protocol_type=self.udp.header_type,
                                            ttl=ip_ttl,
                                            identification=ip_ident,
                                            exit_on_failure=exit_on_failure,
                                            exit_code=exit_code,
                                            quiet=quiet,
                                            source_ip=ip_src,
                                            destination_ip=ip_dst)

            packet += self.udp.make_header(data_length=len(dns_packet),
                                           exit_on_failure=exit_on_failure,
                                           exit_code=exit_code,
                                           quiet=quiet,
                                           source_port=udp_src_port,
                                           destination_port=udp_dst_port)

            return packet + dns_packet

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'destination_mac' in traceback_text:
                error_text += ' Bad source or destination MAC address!'
            if 'destination_ip' in traceback_text:
                error_text += ' Bad source or destination IP address!'
            if 'destination_port' in traceback_text:
                error_text += ' Bad source or destination UDP port!'

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'transaction_id' in traceback_text:
                error_text += ' Bad transaction ID: ' + self.base.error_text(str(transaction_id)) + \
                              ' transaction ID must be in range: ' + self.base.info_text('1 - 65535')
            if 'flags' in traceback_text:
                error_text += ' Bad flags: ' + self.base.error_text(str(flags)) + \
                              ' flags must be in range: ' + self.base.info_text('1 - 65535')
            if 'type' in traceback_text:
                error_text += ' Query type be in range: ' + self.base.info_text('1 - 65535')
            if 'class' in traceback_text:
                error_text += ' Query class must be in range: ' + self.base.info_text('1 - 65535')

        except KeyError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'class' in traceback_text:
                error_text += ' Query class not find in queries!'
            if 'type' in traceback_text:
                error_text += ' Query type not find in queries!'
            if 'name' in traceback_text:
                error_text += ' Query name not find in queries!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_ipv6_request_packet(self,
                                 ethernet_src_mac: str = '01:23:45:67:89:0a',
                                 ethernet_dst_mac: str = '01:23:45:67:89:0b',
                                 ip_src: str = 'fd00::1',
                                 ip_dst: str = 'fd00::2',
                                 ip_ttl: int = 64,
                                 udp_src_port: int = 5353,
                                 udp_dst_port: int = 53,
                                 transaction_id: int = 1,
                                 queries: List[Dict[str, Union[int, str]]] =
                                 [{'type': 1, 'class': 1, 'name': 'test.com'}],
                                 flags=0,
                                 exit_on_failure: bool = False,
                                 exit_code: int = 70,
                                 quiet: bool = False) -> Union[None, bytes]:
        """
        Make DNS request packet for IPv6 network
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ip_src: Source IPv6 address string in Network header (example: 'fd00::1')
        :param ip_dst: Destination IPv6 address string in Network header (example: 'fd00::2')
        :param ip_ttl: Hop limit for IPv6 header (default: 64)
        :param udp_src_port: Source UDP port (example: 5353)
        :param udp_dst_port: Source UDP port (default: 53)
        :param transaction_id: DNS transaction id integer (example: 1)
        :param flags: DNS flags (default: 0)
        :param queries: List with DNS queries (example: [{'type': 1, 'class': 1, 'name': 'test.com'}])
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 70)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        error_text: str = 'Failed to make IPv6 DNS request packet!'
        packet: bytes = b''
        try:
            dns_packet: bytes = b''
            dns_packet += pack('!H', transaction_id)  # DNS transaction ID
            dns_packet += pack('!H', flags)           # DNS flags
            dns_packet += pack('!H', len(queries))    # Questions
            dns_packet += pack('!H', 0)               # Answer RRs
            dns_packet += pack('!H', 0)               # Authority RRs
            dns_packet += pack('!H', 0)               # Additionsl RRS

            for query in queries:
                dns_packet += self.pack_dns_name(query['name'])
                dns_packet += pack('!H', query['type'])
                dns_packet += pack('!H', query['class'])

            packet += self.eth.make_header(network_type=self.ipv6.header_type,
                                           exit_on_failure=exit_on_failure,
                                           exit_code=exit_code,
                                           quiet=quiet,
                                           source_mac=ethernet_src_mac,
                                           destination_mac=ethernet_dst_mac)

            packet += self.ipv6.make_header(traffic_class=0,
                                            flow_label=0,
                                            payload_len=self.udp.header_length + len(dns_packet),
                                            next_header=self.udp.header_type,
                                            hop_limit=ip_ttl,
                                            exit_on_failure=exit_on_failure,
                                            exit_code=exit_code,
                                            quiet=quiet,
                                            source_ip=ip_src,
                                            destination_ip=ip_dst)

            packet += self.udp.make_header_with_ipv6_checksum(ipv6_src=ip_src,
                                                              ipv6_dst=ip_dst,
                                                              payload_len=len(dns_packet),
                                                              payload_data=dns_packet,
                                                              exit_on_failure=exit_on_failure,
                                                              exit_code=exit_code,
                                                              quiet=quiet,
                                                              port_src=udp_src_port,
                                                              port_dst=udp_dst_port)

            return packet + dns_packet

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'destination_mac' in traceback_text:
                error_text += ' Bad source or destination MAC address!'
            if 'destination_ip' in traceback_text:
                error_text += ' Bad source or destination IPv6 address!'
            if 'port_dst' in traceback_text:
                error_text += ' Bad source or destination UDP port!'

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'transaction_id' in traceback_text:
                error_text += ' Bad transaction ID: ' + self.base.error_text(str(transaction_id)) + \
                              ' transaction ID must be in range: ' + self.base.info_text('1 - 65535')
            if 'flags' in traceback_text:
                error_text += ' Bad flags: ' + self.base.error_text(str(flags)) + \
                              ' flags must be in range: ' + self.base.info_text('1 - 65535')
            if 'type' in traceback_text:
                error_text += ' Query type be in range: ' + self.base.info_text('1 - 65535')
            if 'class' in traceback_text:
                error_text += ' Query class must be in range: ' + self.base.info_text('1 - 65535')

        except KeyError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'class' in traceback_text:
                error_text += ' Query class not find in queries!'
            if 'type' in traceback_text:
                error_text += ' Query type not find in queries!'
            if 'name' in traceback_text:
                error_text += ' Query name not find in queries!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_a_query(self,
                     ethernet_src_mac: str = '01:23:45:67:89:0a',
                     ethernet_dst_mac: str = '01:23:45:67:89:0b',
                     ip_src: str = '192.168.1.1',
                     ip_dst: str = '192.168.1.2',
                     udp_src_port: int = 5353,
                     udp_dst_port: int = 53,
                     transaction_id: int = 1,
                     name: str = 'test.com',
                     flags: int = 0,
                     exit_on_failure: bool = False,
                     exit_code: int = 71,
                     quiet: bool = False) -> Union[None, bytes]:
        """
        Make DNS query with type: A
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ip_src: Source IPv4 or IPv6 address string in Network header (example: '192.168.1.1')
        :param ip_dst: Destination IPv4 or IPv6 address string in Network header (example: '192.168.1.2')
        :param udp_src_port: Source UDP port (example: 5353)
        :param udp_dst_port: Source UDP port (default: 53)
        :param transaction_id: DNS transaction id integer (example: 1)
        :param name: Name of domain for resolving (example: test.com)
        :param flags: DNS flags (default: 0)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 71)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        queries: List[Dict[str, Union[int, str]]] = [{'type': 1, 'class': 1, 'name': name}]

        if self.base.ip_address_validation(ip_src):
            return self.make_ipv4_request_packet(ethernet_src_mac=ethernet_src_mac, ethernet_dst_mac=ethernet_dst_mac,
                                                 ip_src=ip_src, ip_dst=ip_dst,
                                                 udp_src_port=udp_src_port, udp_dst_port=udp_dst_port,
                                                 transaction_id=transaction_id,
                                                 flags=flags,
                                                 queries=queries)

        elif self.base.ipv6_address_validation(ip_src):
            return self.make_ipv6_request_packet(ethernet_src_mac=ethernet_src_mac, ethernet_dst_mac=ethernet_dst_mac,
                                                 ip_src=ip_src, ip_dst=ip_dst,
                                                 udp_src_port=udp_src_port, udp_dst_port=udp_dst_port,
                                                 transaction_id=transaction_id,
                                                 flags=flags,
                                                 queries=queries)

        else:
            if not quiet:
                self.base.print_error('Failed to make DNS query with type: A! Unknown network type!')
            if exit_on_failure:
                exit(exit_code)
            return None

    def make_aaaa_query(self,
                        ethernet_src_mac: str = '01:23:45:67:89:0a',
                        ethernet_dst_mac: str = '01:23:45:67:89:0b',
                        ip_src: str = '192.168.1.1',
                        ip_dst: str = '192.168.1.2',
                        udp_src_port: int = 5353,
                        udp_dst_port: int = 53,
                        transaction_id: int = 1,
                        name: str = 'test.com',
                        flags: int = 0,
                        exit_on_failure: bool = False,
                        exit_code: int = 72,
                        quiet: bool = False) -> Union[None, bytes]:
        """
        Make DNS query with type: AAAA
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ip_src: Source IPv4 or IPv6 address string in Network header (example: '192.168.1.1')
        :param ip_dst: Destination IPv4 or IPv6 address string in Network header (example: '192.168.1.2')
        :param udp_src_port: Source UDP port (example: 5353)
        :param udp_dst_port: Source UDP port (default: 53)
        :param transaction_id: DNS transaction id integer (example: 1)
        :param name: Name of domain for resolving (example: test.com)
        :param flags: DNS flags (default: 0)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 72)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        queries: List[Dict[str, Union[int, str]]] = [{'type': 28, 'class': 1, 'name': name}]

        if self.base.ip_address_validation(ip_src):
            return self.make_ipv4_request_packet(ethernet_src_mac=ethernet_src_mac, ethernet_dst_mac=ethernet_dst_mac,
                                                 ip_src=ip_src, ip_dst=ip_dst,
                                                 udp_src_port=udp_src_port, udp_dst_port=udp_dst_port,
                                                 transaction_id=transaction_id,
                                                 flags=flags,
                                                 queries=queries)

        elif self.base.ipv6_address_validation(ip_src):
            return self.make_ipv6_request_packet(ethernet_src_mac=ethernet_src_mac, ethernet_dst_mac=ethernet_dst_mac,
                                                 ip_src=ip_src, ip_dst=ip_dst,
                                                 udp_src_port=udp_src_port, udp_dst_port=udp_dst_port,
                                                 transaction_id=transaction_id,
                                                 flags=flags,
                                                 queries=queries)

        else:
            if not quiet:
                self.base.print_error('Failed to make DNS query with type: AAAA! Unknown network type!')
            if exit_on_failure:
                exit(exit_code)
            return None

    def make_any_query(self,
                       ethernet_src_mac: str = '01:23:45:67:89:0a',
                       ethernet_dst_mac: str = '01:23:45:67:89:0b',
                       ip_src: str = '192.168.1.1',
                       ip_dst: str = '192.168.1.2',
                       udp_src_port: int = 5353,
                       udp_dst_port: int = 53,
                       transaction_id: int = 1,
                       name: str = 'test.com',
                       flags: int = 0,
                       exit_on_failure: bool = False,
                       exit_code: int = 73,
                       quiet: bool = False) -> Union[None, bytes]:
        """
        Make DNS query with type: ANY
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ip_src: Source IPv4 or IPv6 address string in Network header (example: '192.168.1.1')
        :param ip_dst: Destination IPv4 or IPv6 address string in Network header (example: '192.168.1.2')
        :param udp_src_port: Source UDP port (example: 5353)
        :param udp_dst_port: Source UDP port (default: 53)
        :param transaction_id: DNS transaction id integer (example: 1)
        :param name: Name of domain for resolving (example: test.com)
        :param flags: DNS flags (default: 0)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 69)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        queries: List[Dict[str, Union[int, str]]] = [{'type': 255, 'class': 1, 'name': name}]

        if self.base.ip_address_validation(ip_src):
            return self.make_ipv4_request_packet(ethernet_src_mac=ethernet_src_mac, ethernet_dst_mac=ethernet_dst_mac,
                                                 ip_src=ip_src, ip_dst=ip_dst,
                                                 udp_src_port=udp_src_port, udp_dst_port=udp_dst_port,
                                                 transaction_id=transaction_id,
                                                 flags=flags,
                                                 queries=queries)

        elif self.base.ipv6_address_validation(ip_src):
            return self.make_ipv6_request_packet(ethernet_src_mac=ethernet_src_mac, ethernet_dst_mac=ethernet_dst_mac,
                                                 ip_src=ip_src, ip_dst=ip_dst,
                                                 udp_src_port=udp_src_port, udp_dst_port=udp_dst_port,
                                                 transaction_id=transaction_id,
                                                 flags=flags,
                                                 queries=queries)

        else:
            if not quiet:
                self.base.print_error('Failed to make DNS query with type: ANY! Unknown network type!')
            if exit_on_failure:
                exit(exit_code)
            return None

    def make_ns_query(self,
                      ethernet_src_mac: str = '01:23:45:67:89:0a',
                      ethernet_dst_mac: str = '01:23:45:67:89:0b',
                      ip_src: str = '192.168.1.1',
                      ip_dst: str = '192.168.1.2',
                      udp_src_port: int = 5353,
                      udp_dst_port: int = 53,
                      transaction_id: int = 1,
                      name: str = 'test.com',
                      flags: int = 0,
                      exit_on_failure: bool = False,
                      exit_code: int = 74,
                      quiet: bool = False) -> Union[None, bytes]:
        """
        Make DNS query with type: NS
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ip_src: Source IPv4 or IPv6 address string in Network header (example: '192.168.1.1')
        :param ip_dst: Destination IPv4 or IPv6 address string in Network header (example: '192.168.1.2')
        :param udp_src_port: Source UDP port (example: 5353)
        :param udp_dst_port: Source UDP port (default: 53)
        :param transaction_id: DNS transaction id integer (example: 1)
        :param name: Name of domain for resolving (example: test.com)
        :param flags: DNS flags (default: 0)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 69)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of packet or None if error
        """
        queries: List[Dict[str, Union[int, str]]] = [{'type': 2, 'class': 1, 'name': name}]

        if self.base.ip_address_validation(ip_src):
            return self.make_ipv4_request_packet(ethernet_src_mac=ethernet_src_mac, ethernet_dst_mac=ethernet_dst_mac,
                                                 ip_src=ip_src, ip_dst=ip_dst,
                                                 udp_src_port=udp_src_port, udp_dst_port=udp_dst_port,
                                                 transaction_id=transaction_id,
                                                 flags=flags,
                                                 queries=queries)

        elif self.base.ipv6_address_validation(ip_src):
            return self.make_ipv6_request_packet(ethernet_src_mac=ethernet_src_mac, ethernet_dst_mac=ethernet_dst_mac,
                                                 ip_src=ip_src, ip_dst=ip_dst,
                                                 udp_src_port=udp_src_port, udp_dst_port=udp_dst_port,
                                                 transaction_id=transaction_id,
                                                 flags=flags,
                                                 queries=queries)

        else:
            if not quiet:
                self.base.print_error('Failed to make DNS query with type: NS! Unknown network type!')
            if exit_on_failure:
                exit(exit_code)
            return None
# endregion


# region Raw DHCPv4
class RawDHCPv4:
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
    # +---------------+---------------+---------------+---------------+
    # |                            xid (4)                            |
    # +-------------------------------+-------------------------------+
    # |           secs (2)            |           flags (2)           |
    # +-------------------------------+-------------------------------+
    # |                          ciaddr  (4)                          |
    # +---------------------------------------------------------------+
    # |                          yiaddr  (4)                          |
    # +---------------------------------------------------------------+
    # |                          siaddr  (4)                          |
    # +---------------------------------------------------------------+
    # |                          giaddr  (4)                          |
    # +---------------------------------------------------------------+
    # |                                                               |
    # |                          chaddr  (16)                         |
    # |                                                               |
    # |                                                               |
    # +---------------------------------------------------------------+
    # |                                                               |
    # |                          sname   (64)                         |
    # +---------------------------------------------------------------+
    # |                                                               |
    # |                          file    (128)                        |
    # +---------------------------------------------------------------+
    # |                                                               |
    # |                          options (variable)                   |
    # +---------------------------------------------------------------+

    # FIELD      OCTETS       DESCRIPTION
    # -----      ------       -----------
    #
    # op            1  Message op code / message type.
    #                  1 = BOOTREQUEST, 2 = BOOTREPLY
    # htype         1  Hardware address type, see ARP section in 'Assigned
    #                  Numbers' RFC; e.g., '1' = 10mb ethernet.
    # hlen          1  Hardware address length (e.g.  '6' for 10mb
    #                  ethernet).
    # hops          1  Client sets to zero, optionally used by relay agents
    #                  when booting via a relay agent.
    # xid           4  Transaction ID, a random number chosen by the
    #                  client, used by the client and server to associate
    #                  messages and responses between a client and a
    #                  server.
    # secs          2  Filled in by client, seconds elapsed since client
    #                  began address acquisition or renewal process.
    # flags         2  Flags (see figure 2).
    # ciaddr        4  Client IP address; only filled in if client is in
    #                  BOUND, RENEW or REBINDING state and can respond
    #                  to ARP requests.
    # yiaddr        4  'your' (client) IP address.
    # siaddr        4  IP address of next server to use in bootstrap;
    #                  returned in DHCPOFFER, DHCPACK by server.
    # giaddr        4  Relay agent IP address, used in booting via a
    #                  relay agent.
    # chaddr       16  Client hardware address.
    # sname        64  Optional server host name, null terminated string.
    # file        128  Boot file name, null terminated string; 'generic'
    #                  name or null in DHCPDISCOVER, fully qualified
    #                  directory-path name in DHCPOFFER.
    # options     var  Optional parameters field.  See the options
    #                  documents for a list of defined options.

    # region Properties

    # Set minimal BOOTP/DHCPv4 packet length
    bootp_packet_length: int = 236

    # Set DHCPv4 packet offset
    dhcp_packet_offset: int = 240

    # Set DHCPv4 magic cookie
    dhcp_magic_cookie: bytes = b'\x63\x82\x53\x63'

    # Init Raw Ethernet
    eth: RawEthernet = RawEthernet()

    # Init Raw IPv4
    ipv4: RawIPv4 = RawIPv4()

    # Init Raw DNS
    udp: RawUDP = RawUDP()

    # Init Raw-packet Base class
    base: Base = Base()

    # endregion

    def parse_packet(self,
                     packet: bytes,
                     exit_on_failure: bool = False,
                     exit_code: int = 74,
                     quiet: bool = True):
        """
        Parse DHCPv4 packet
        :param packet: Bytes of packet
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 74)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Parsed DHCPv4 packet dictionary (example: {}) or None if error
        """
        error_text: str = 'Failed to parse DHCPv4 packet!'
        bootp_packet: Dict[str, Union[int, str]] = dict()
        dhcp_packet: Dict[int, Union[int, str, bytes]] = dict()
        try:
            assert not len(packet) < RawDHCPv4.bootp_packet_length, \
                ' Bad packet length: ' + self.base.error_text(str(len(packet))) + \
                ' minimal BOOTP/DHCPv4 packet length: ' + self.base.info_text(str(RawDHCPv4.bootp_packet_length))

            bootp_detailed = unpack('!' '4B' 'I' '2H' '4s' '4s' '4s' '4s' '6s', packet[:34])

            bootp_packet['message-type'] = int(bootp_detailed[0])
            bootp_packet['hardware-type'] = int(bootp_detailed[1])
            bootp_packet['hardware-address-length'] = int(bootp_detailed[2])
            bootp_packet['hops'] = int(bootp_detailed[3])
            bootp_packet['transaction-id'] = int(bootp_detailed[4])
            bootp_packet['seconds-elapsed'] = int(bootp_detailed[5])
            bootp_packet['flags'] = int(bootp_detailed[6])
            bootp_packet['client-ip-address'] = inet_ntoa(bootp_detailed[7])
            bootp_packet['your-ip-address'] = inet_ntoa(bootp_detailed[8])
            bootp_packet['server-ip-address'] = inet_ntoa(bootp_detailed[9])
            bootp_packet['relay-ip-address'] = inet_ntoa(bootp_detailed[10])
            bootp_packet['client-mac-address'] = self.eth.convert_mac(mac_address=bootp_detailed[11],
                                                                      exit_on_failure=False)

            if len(packet) > RawDHCPv4.dhcp_packet_offset:
                if packet[RawDHCPv4.bootp_packet_length:RawDHCPv4.dhcp_packet_offset] == RawDHCPv4.dhcp_magic_cookie:

                    position = RawDHCPv4.dhcp_packet_offset

                    while position < len(packet) - 1:
                        option_name = int(unpack('B', packet[position:position + 1])[0])
                        position += 1

                        # 255 - End
                        if option_name == 255:
                            break

                        # 12 - Host name
                        elif option_name == 12:
                            option_length = int(unpack('B', packet[position:position + 1])[0])
                            position += 1
                            option_value = ''.join([str(x) for x in packet[position:position + option_length]])
                            position += option_length

                        # 50 - Requested IP
                        elif option_name == 50:
                            option_value = inet_ntoa(unpack('4s', packet[position + 1:position + 5])[0])
                            position += 5

                        # 51 - Lease time
                        elif option_name == 51:
                            option_value = int(unpack('I', packet[position + 1:position + 5])[0])
                            position += 5

                        # 53 - Message type
                        elif option_name == 53:
                            option_value = int(unpack('B', packet[position + 1:position + 2])[0])
                            position += 2

                        # 54 - DHCP Server Identifier
                        elif option_name == 54:
                            option_value = inet_ntoa(unpack('4s', packet[position + 1:position + 5])[0])
                            position += 5

                        # 57 - Maximum DHCPv4 message size
                        elif option_name == 57:
                            option_value = int(unpack('H', packet[position + 1:position + 3])[0])
                            position += 3

                        # 61 - Client identifier
                        elif option_name == 61:
                            option_value = self.eth.convert_mac(
                                mac_address=unpack('6s', packet[position + 2:position + 8])[0],
                                exit_on_failure=False)
                            position += 8

                        else:
                            option_length = int(unpack('B', packet[position:position + 1])[0])
                            position += 1
                            try:
                                option_value = ''.join([hexlify(x) for x in packet[position:position + option_length]])
                            except TypeError:
                                option_value = ''.join(map(chr, packet[position:position + option_length]))
                            position += option_length

                        dhcp_packet[option_name] = option_value

            return {
                'BOOTP': bootp_packet,
                'DHCPv4': dhcp_packet
            }

        except AssertionError as Error:
            error_text += Error.args[0]

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_packet(self,
                    ethernet_src_mac: str = '01:23:45:67:89:0a',
                    ethernet_dst_mac: str = '01:23:45:67:89:0b',
                    ip_src: str = '192.168.1.1',
                    ip_dst: str = '192.168.1.2',
                    ip_ident: Union[None, int] = None,
                    udp_src_port: int = 68,
                    udp_dst_port: int = 67,
                    bootp_message_type: int = 1,
                    bootp_transaction_id: int = 1,
                    bootp_flags: int = 0,
                    bootp_client_ip: str = '192.168.1.1',
                    bootp_your_client_ip: str = '192.168.1.1',
                    bootp_next_server_ip: str = '192.168.1.1',
                    bootp_relay_agent_ip: str = '192.168.1.1',
                    bootp_client_hw_address: str = '01:23:45:67:89:0a',
                    dhcp_options: bytes = b'',
                    padding: int = 24,
                    exit_on_failure: bool = False,
                    exit_code: int = 75,
                    quiet: bool = False) -> Union[None, bytes]:
        """
        Make DHCPv4 packet
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param ip_src: Source IPv4 address string in Network header (example: '192.168.1.1')
        :param ip_dst: Destination IPv4 address string in Network header (example: '192.168.1.2')
        :param ip_ident: Identification integer value for IPv4 header (optional value)
        :param udp_src_port: Source UDP port (example: 68)
        :param udp_dst_port: Source UDP port (default: 67)
        :param bootp_message_type: BOOTP Message type integer (example: 1 - DHCPv4 Discover)
        :param bootp_transaction_id: BOOTP Transaction ID integer (example: 1)
        :param bootp_flags: BOOTP Flags integer (example: 0)
        :param bootp_client_ip: BOOTP CIADDR - Client IP address (example: '192.168.1.1')
        :param bootp_your_client_ip: BOOTP YIADDR - Your client IP address (example: '192.168.1.1')
        :param bootp_next_server_ip: BOOTP SIADDR - Next server IP address (example: '192.168.1.1')
        :param bootp_relay_agent_ip: BOOTP GIADDR - Relay agent IP address (example: '192.168.1.1')
        :param bootp_client_hw_address: BOOTP CHADDR - Client hardware address (example: '01:23:45:67:89:0a')
        :param dhcp_options: Bytes of DHCPv4 options (example: b'')
        :param padding: Number of padding bytes integer (default: 24)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 75)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of DHCPv4 packet or None if error
        """
        error_text: str = 'Failed to make DHCPv4 packet!'
        dhcp_packet: bytes = b''
        packet: bytes = b''
        try:
            dhcp_packet += pack('!B', bootp_message_type)  # Message type
            dhcp_packet += pack('!B', 1)    # Hardware type: 1 - Ethernet
            dhcp_packet += pack('!B', 6)    # Hardware address length: 6 - Ethernet header length
            dhcp_packet += pack('!B', 0)                     # Number of hops
            dhcp_packet += pack('!L', bootp_transaction_id)  # Transaction ID
            dhcp_packet += pack('!H', 0)                     # Seconds elapsed
            dhcp_packet += pack('!H', bootp_flags)           # Flags
            dhcp_packet += pack('!4s', inet_aton(bootp_client_ip))       # CIADDR - Client IP address
            dhcp_packet += pack('!4s', inet_aton(bootp_your_client_ip))  # YIADDR - Your client IP address
            dhcp_packet += pack('!4s', inet_aton(bootp_next_server_ip))  # SIADDR - Next server IP address
            dhcp_packet += pack('!4s', inet_aton(bootp_relay_agent_ip))  # GIADDR - Relay agent IP address

            # CHADDR - Client hardware address
            dhcp_packet += self.eth.convert_mac(mac_address=bootp_client_hw_address,
                                                exit_on_failure=exit_on_failure,
                                                exit_code=exit_code,
                                                quiet=quiet)

            dhcp_packet += b''.join(pack('B', 0) for _ in range(10))   # Client hardware address padding
            dhcp_packet += b''.join(pack('B', 0) for _ in range(64))   # Server host name
            dhcp_packet += b''.join(pack('B', 0) for _ in range(128))  # Boot file name
            dhcp_packet += RawDHCPv4.dhcp_magic_cookie                 # DHCPv4 magic cookie

            # Add padding bytes in end of DHCPv4 packet
            dhcp_packet += dhcp_options + b''.join(pack('B', 0) for _ in range(int(padding)))

            # Make Ethernet header
            packet += self.eth.make_header(network_type=self.ipv4.header_type,
                                           exit_on_failure=exit_on_failure,
                                           exit_code=exit_code,
                                           quiet=quiet,
                                           source_mac=ethernet_src_mac,
                                           destination_mac=ethernet_dst_mac)

            # Make IPv4 header
            packet += self.ipv4.make_header(data_len=len(dhcp_packet),
                                            transport_protocol_len=self.udp.header_length,
                                            transport_protocol_type=self.udp.header_type,
                                            ttl=64,
                                            identification=ip_ident,
                                            exit_on_failure=exit_on_failure,
                                            exit_code=exit_code,
                                            quiet=quiet,
                                            source_ip=ip_src,
                                            destination_ip=ip_dst)

            # Make UDP header
            packet += self.udp.make_header(data_length=len(dhcp_packet),
                                           exit_on_failure=exit_on_failure,
                                           exit_code=exit_code,
                                           quiet=quiet,
                                           source_port=udp_src_port,
                                           destination_port=udp_dst_port)

            return packet + dhcp_packet

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'destination_mac' in traceback_text:
                error_text += ' Bad source or destination MAC address!'
            if 'destination_ip' in traceback_text:
                error_text += ' Bad source or destination IP address!'
            if 'destination_port' in traceback_text:
                error_text += ' Bad source or destination UDP port!'

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'bootp_message_type' in traceback_text:
                error_text += ' Bad BOOTP message type: ' + self.base.error_text(str(bootp_message_type)) + \
                              ' BOOTP message type must be in range: ' + self.base.info_text('1 - 255')
            if 'bootp_transaction_id' in traceback_text:
                error_text += ' Bad BOOTP transaction ID: ' + self.base.error_text(str(bootp_transaction_id)) + \
                              ' BOOTP transaction ID must be in range: ' + self.base.info_text('1 - 4294967295')
            if 'bootp_message_type' in traceback_text:
                error_text += ' Bad BOOTP flags: ' + self.base.error_text(str(bootp_message_type)) + \
                              ' BOOTP flags must be in range: ' + self.base.info_text('1 - 65535')

        except sock_error:
            pass

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_discover_packet(self,
                             ethernet_src_mac: str = '01:23:45:67:89:0a',
                             ethernet_dst_mac: Union[None, str] = None,
                             ip_src: Union[None, str] = None,
                             ip_dst: Union[None, str] = None,
                             ip_ident: Union[None, int] = None,
                             client_mac: str = '01:23:45:67:89:0a',
                             host_name: Union[None, str] = None,
                             relay_agent_ip: Union[None, str] = None,
                             transaction_id: Union[None, int] = None,
                             exit_on_failure: bool = False,
                             exit_code: int = 76,
                             quiet: bool = False) -> Union[None, bytes]:
        """
        Make DHCPv4 Discover packet
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (default: 'ff:ff:ff:ff:ff:ff')
        :param ip_src: Source IPv4 address string in Network header (default: '0.0.0.0')
        :param ip_dst: Destination IPv4 address string in Network header (default: '255.255.255.255')
        :param ip_ident: Identification integer value for IPv4 header (optional value)
        :param udp_src_port: Source UDP port (default: 68)
        :param udp_dst_port: Source UDP port (default: 67)
        :param client_mac: BOOTP CHADDR - Client hardware address (example: '01:23:45:67:89:0a')
        :param host_name: Client hostname (example: 'test')
        :param relay_agent_ip: BOOTP GIADDR - Relay agent IP address (default: '0.0.0.0')
        :param transaction_id: BOOTP Transaction ID integer (example: 1)
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 75)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of DHCPv4 Discover packet or None if error
        """
        error_text: str = 'Failed to make DHCPv4 Discover packet!'
        try:
            if ethernet_dst_mac is None:
                ethernet_dst_mac = 'ff:ff:ff:ff:ff:ff'

            if ip_src is None:
                ip_src = '0.0.0.0'

            if ip_dst is None:
                ip_dst = '255.255.255.255'

            if relay_agent_ip is None:
                relay_agent_ip = '0.0.0.0'

            if transaction_id is None:
                transaction_id = randint(1, 4294967295)

            # 53 - DHCPv4 message type option; 1 - length of option value; 1 - DHCPv4 Discover request
            dhcp_options: bytes = pack('!3B', 53, 1, 1)

            # 12 - DHCPv4 hostname option
            if host_name is not None:
                host_name: bytes = host_name.encode('utf-8')
                dhcp_options += pack('!2B', 12, len(host_name)) + host_name

            # 55 - DHCPv4 parameter requets list
            dhcp_options += pack('!2B', 55, 254)
            for param in range(1, 255):
                dhcp_options += pack('B', param)

            # 255 - End of DHCPv4 options
            dhcp_options += pack('B', 255)  # End of options

            return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                    ethernet_dst_mac=ethernet_dst_mac,
                                    ip_src=ip_src,
                                    ip_dst=ip_dst,
                                    ip_ident=ip_ident,
                                    udp_src_port=68,
                                    udp_dst_port=67,
                                    bootp_message_type=1,
                                    bootp_transaction_id=transaction_id,
                                    bootp_flags=0,
                                    bootp_client_ip='0.0.0.0',
                                    bootp_your_client_ip='0.0.0.0',
                                    bootp_next_server_ip='0.0.0.0',
                                    bootp_relay_agent_ip=relay_agent_ip,
                                    bootp_client_hw_address=client_mac,
                                    dhcp_options=dhcp_options,
                                    exit_on_failure=exit_on_failure,
                                    exit_code=exit_code,
                                    quiet=quiet)

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'host_name' in traceback_text:
                error_text += ' Bad host name! Maximum host name length: ' + self.base.info_text('255')

        except UnicodeEncodeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'host_name' in traceback_text:
                error_text += ' Bad host name: ' + self.base.error_text(str(host_name))

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_request_packet(self,
                            ethernet_src_mac: str = '01:23:45:67:89:0a',
                            ethernet_dst_mac: Union[None, str] = None,
                            ip_src: Union[None, str] = None,
                            ip_dst: Union[None, str] = None,
                            ip_ident: Union[None, int] = None,
                            dhcp_message_type: int = 3,
                            client_mac: str = '01:23:45:67:89:0a',
                            client_ip: Union[None, str] = None,
                            your_client_ip: Union[None, str] = None,
                            relay_agent_ip: Union[None, str] = None,
                            host_name: Union[None, str] = None,
                            transaction_id: Union[None, int] = None,
                            requested_ip: Union[None, str] = None,
                            option_code: Union[None, int] = None,
                            option_value: Union[None, bytes] = None,
                            exit_on_failure: bool = False,
                            exit_code: int = 77,
                            quiet: bool = False) -> Union[None, bytes]:
        error_text: str = 'Failed to make request DHCPv4 packet!'
        try:
            if ethernet_dst_mac is None:
                ethernet_dst_mac = 'ff:ff:ff:ff:ff:ff'

            if ip_src is None:
                ip_src = '0.0.0.0'

            if ip_dst is None:
                ip_dst = '255.255.255.255'

            if client_ip is None:
                client_ip = '0.0.0.0'

            if your_client_ip is None:
                your_client_ip = '0.0.0.0'

            if relay_agent_ip is None:
                relay_agent_ip = '0.0.0.0'

            if transaction_id is None:
                transaction_id = randint(1, 4294967295)

            # 53 - DHCPv4 message type option; 1 - length of option value;
            # 1 - DHCPv4 Discover, 3 - DHCPv4 Request
            dhcp_options: bytes = pack('!3B', 53, 1, dhcp_message_type)  # Set DHCPv4 message type

            # 50 - DHCPv4 requested IP address
            if requested_ip is not None:
                dhcp_options += pack('!' '2B' '4s', 50, 4, inet_aton(requested_ip))

            # 12 - DHCPv4 hostname option
            if host_name is not None:
                    host_name: bytes = host_name.encode('utf-8')
                    dhcp_options += pack('!2B', 12, len(host_name)) + host_name

            # Set custom DHCPv4 option
            if option_value is not None and option_code is not None:
                dhcp_options += pack('!' '2B', option_code, len(option_value)) + option_value

            # 55 - DHCPv4 parameter requets list
            dhcp_options += pack('!2B', 55, 7)
            for param in [1, 2, 3, 6, 28, 15, 26]:
                dhcp_options += pack('B', param)

            # 255 - End of DHCPv4 options
            dhcp_options += pack('B', 255)

            return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                    ethernet_dst_mac=ethernet_dst_mac,
                                    ip_src=ip_src,
                                    ip_dst=ip_dst,
                                    ip_ident=ip_ident,
                                    udp_src_port=68,
                                    udp_dst_port=67,
                                    bootp_message_type=1,
                                    bootp_transaction_id=transaction_id,
                                    bootp_flags=0,
                                    bootp_client_ip=client_ip,
                                    bootp_your_client_ip=your_client_ip,
                                    bootp_next_server_ip='0.0.0.0',
                                    bootp_relay_agent_ip=relay_agent_ip,
                                    bootp_client_hw_address=client_mac,
                                    dhcp_options=dhcp_options,
                                    exit_on_failure=exit_on_failure,
                                    exit_code=exit_code,
                                    quiet=quiet)

        except OSError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'requested_ip' in traceback_text:
                error_text += ' Bad requested IPv4 address: ' + self.base.error_text(str(requested_ip)) + \
                              ' example IPv4 address: ' + self.base.info_text('192.168.1.1')

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'host_name' in traceback_text:
                error_text += ' Bad host name! Maximum host name length: ' + self.base.info_text('255')
            if 'dhcp_message_type' in traceback_text:
                error_text += ' Bad DHCPv4 message type: ' + self.base.error_text(str(dhcp_message_type)) + \
                              ' DHCPv4 message type must be in range: ' + self.base.info_text('1 - 255')
            if 'option_code' in traceback_text:
                error_text += ' Bad option code or value! Option code must be in range: ' + \
                              self.base.info_text('1 - 255') + ' maximum option value length: ' + \
                              self.base.info_text('255')

        except UnicodeEncodeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'host_name' in traceback_text:
                error_text += ' Bad host name: ' + self.base.error_text(str(host_name))

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_response_packet(self,
                             ethernet_src_mac: str = '01:23:45:67:89:0a',
                             ethernet_dst_mac: Union[None, str] = None,
                             ip_src: str = '192.168.1.1',
                             ip_dst: Union[None, str] = None,
                             ip_ident: Union[None, int] = None,
                             transaction_id: int = 1,
                             dhcp_message_type: int = 2,
                             your_client_ip: str = '192.168.1.2',
                             client_mac: Union[None, str] = None,
                             dhcp_server_id: Union[None, str] = None,
                             lease_time: int = 65535,
                             netmask: str = '255.255.255.0',
                             router: str = '192.168.1.1',
                             dns: str = '192.168.1.1',
                             payload_option_code=114,
                             payload: Union[None, bytes] = None,
                             proxy: Union[None, bytes] = None,
                             domain: Union[None, bytes] = None,
                             tftp: Union[None, str] = None,
                             wins: Union[None, str] = None,
                             exit_on_failure: bool = False,
                             exit_code: int = 78,
                             quiet: bool = False) -> Union[None, bytes]:
        error_text: str = 'Failed to make request DHCPv4 packet!'
        try:
            if ethernet_dst_mac is None:
                ethernet_dst_mac = 'ff:ff:ff:ff:ff:ff'

            if ip_dst is None:
                ip_dst = '255.255.255.255'

            if client_mac is None:
                client_mac = ethernet_dst_mac

            if dhcp_server_id is None:
                dhcp_server_id = ip_src

            # 53 - DHCPv4 message type option; 1 - length of option value;
            # 2 - DHCPv4 Offer, 4 - DHCPv4 Decline, 5 - DHCPv4 ACK
            dhcp_options: bytes = pack('!3B', 53, 1, dhcp_message_type)

            # 54 - DHCPv4 Server identifier option (Server IPv4 address)
            dhcp_options += pack('!' '2B' '4s', 54, 4, inet_aton(dhcp_server_id))

            # 51 - DHCPv4 IP address lease time option
            dhcp_options += pack('!' '2B' 'L', 51, 4, lease_time)

            # 1 - DHCPv4 Subnet mask option
            dhcp_options += pack('!' '2B' '4s', 1, 4, inet_aton(netmask))

            # 3 - DHCPv4 Router option (Router IPv4 address)
            dhcp_options += pack('!' '2B' '4s', 3, 4, inet_aton(router))

            # 6 - DHCPv4 DNS option (Domain name server IPv4 address)
            dhcp_options += pack('!' '2B' '4s', 6, 4, inet_aton(dns))

            # 15 - DHCPv4 Domain name option
            if domain is not None:
                dhcp_options += pack('!' '2B', 15, len(domain)) + domain

            # 252 - DHCPv4 Proxy option
            if proxy is not None:
                dhcp_options += pack('!' '2B', 252, len(proxy)) + proxy

            # Custom DHCPv4 option
            if payload is not None:
                dhcp_options += pack('!' '2B', payload_option_code, len(payload)) + payload

            # 252 - DHCPv4 TFTP server option (TFTP server IPv4 address)
            if tftp is not None:
                dhcp_options += pack('!' '2B' '4s', 150, 4, inet_aton(tftp))

            # WINS server IP address
            if wins is not None:
                # NetBIOS over TCP/IP Name Server Option
                # https://tools.ietf.org/html/rfc1533#section-8.5
                dhcp_options += pack('!' '2B' '4s', 44, 4, inet_aton(wins))

                # NetBIOS over TCP/IP Datagram Distribution Server Option
                # https://tools.ietf.org/html/rfc1533#section-8.6
                dhcp_options += pack('!' '2B' '4s', 45, 4, inet_aton(wins))

                # NetBIOS over TCP/IP Node Type Option
                # https://tools.ietf.org/html/rfc1533#section-8.7
                # 0x2 - P-node (POINT-TO-POINT (P) NODES)
                # https://tools.ietf.org/html/rfc1001#section-10.2
                dhcp_options += pack('!' '3B', 46, 1, 0x2)

            # 255 - End of DHCPv4 options
            dhcp_options += pack('B', 255)

            return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                    ethernet_dst_mac=ethernet_dst_mac,
                                    ip_src=ip_src,
                                    ip_dst=ip_dst,
                                    ip_ident=ip_ident,
                                    udp_src_port=67,
                                    udp_dst_port=68,
                                    bootp_message_type=2,
                                    bootp_transaction_id=transaction_id,
                                    bootp_flags=0,
                                    bootp_client_ip='0.0.0.0',
                                    bootp_your_client_ip=your_client_ip,
                                    bootp_next_server_ip='0.0.0.0',
                                    bootp_relay_agent_ip='0.0.0.0',
                                    bootp_client_hw_address=client_mac,
                                    dhcp_options=dhcp_options)

        except OSError as Error:
            pass

        except struct_error as Error:
            pass

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_release_packet(self,
                            ethernet_src_mac: str = '01:23:45:67:89:0b',
                            ethernet_dst_mac: str = '01:23:45:67:89:0a',
                            ip_src: str = '192.168.1.2',
                            ip_dst: str = '192.168.1.1',
                            exit_on_failure: bool = False,
                            exit_code: int = 78,
                            quiet: bool = False):
        error_text: str = 'Failed to make DHCPv4 Release packet!'
        try:
            options: bytes = pack('!3B', 53, 1, 7)
            options += pack('!' '2B' '4s', 54, 4, inet_aton(ip_dst))
            options += pack('B', 255)

            return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                    ethernet_dst_mac=ethernet_dst_mac,
                                    ip_src=ip_src,
                                    ip_dst=ip_dst,
                                    udp_src_port=68,
                                    udp_dst_port=67,
                                    bootp_message_type=1,
                                    bootp_transaction_id=randint(1, 4294967295),
                                    bootp_flags=0,
                                    bootp_client_ip='0.0.0.0',
                                    bootp_your_client_ip='0.0.0.0',
                                    bootp_next_server_ip='0.0.0.0',
                                    bootp_relay_agent_ip='0.0.0.0',
                                    bootp_client_hw_address=ethernet_src_mac,
                                    dhcp_options=options,
                                    exit_on_failure=exit_on_failure,
                                    exit_code=exit_code,
                                    quiet=quiet)
        except OSError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'requested_ip' in traceback_text:
                error_text += ' Bad destination IPv4 address: ' + self.base.error_text(str(ip_dst)) + \
                              ' example IPv4 address: ' + self.base.info_text('192.168.1.1')

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        return None

    def make_decline_packet(self, relay_mac, relay_ip, server_mac, server_ip, client_mac, requested_ip, transaction_id):
        option_message_type = pack('!3B', 53, 1, 4)
        option_requested_ip = pack('!' '2B' '4s', 50, 4, inet_aton(requested_ip))
        option_server_id = pack('!' '2B' '4s', 54, 4, inet_aton(server_ip))
        option_end = pack('B', 255)

        options = option_message_type + option_requested_ip + option_server_id + option_end

        return self.make_packet(ethernet_src_mac=relay_mac,
                                ethernet_dst_mac=server_mac,
                                ip_src=relay_ip, ip_dst=server_ip,
                                udp_src_port=68, udp_dst_port=67,
                                bootp_message_type=1,
                                bootp_transaction_id=transaction_id,
                                bootp_flags=0,
                                bootp_client_ip=requested_ip,
                                bootp_your_client_ip='0.0.0.0',
                                bootp_next_server_ip='0.0.0.0',
                                bootp_relay_agent_ip=relay_ip,
                                bootp_client_hw_address=client_mac,
                                dhcp_options=options)

    def make_nak_packet(self,
                        ethernet_src_mac: str = '01:23:45:67:89:0b',
                        ethernet_dst_mac: str = '01:23:45:67:89:0a',
                        ip_src: str = '192.168.1.1',
                        ip_dst: str = '192.168.1.2',
                        ip_ident: Union[None, int] = None,
                        transaction_id: int = 1,
                        your_client_ip: str = '192.168.1.2',
                        client_mac: str = '01:23:45:67:89:0a',
                        dhcp_server_id: Union[None, str] = None) -> Union[None, bytes]:

        if dhcp_server_id is None:
            dhcp_server_id: str = ip_src

        option_operation = pack('!3B', 53, 1, 6)
        option_server_id = pack('!' '2B' '4s', 54, 4, inet_aton(dhcp_server_id))
        option_end = pack('B', 255)
        options = option_operation + option_server_id + option_end

        return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                ethernet_dst_mac=ethernet_dst_mac,
                                ip_src=ip_src, ip_dst=ip_dst,
                                ip_ident=ip_ident,
                                udp_src_port=67, udp_dst_port=68,
                                bootp_message_type=2,
                                bootp_transaction_id=transaction_id,
                                bootp_flags=0,
                                bootp_client_ip='0.0.0.0',
                                bootp_your_client_ip=your_client_ip,
                                bootp_next_server_ip='0.0.0.0',
                                bootp_relay_agent_ip='0.0.0.0',
                                bootp_client_hw_address=client_mac,
                                dhcp_options=options)
# endregion


# region Raw ICMPv4
class RawICMPv4:

    # region Properties
    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    ip: RawIPv4 = RawIPv4()
    udp: RawUDP = RawUDP()
    packet_length: int = 4
    packet_type: int = 1
    # endregion

    @staticmethod
    def checksum(packet: bytes) -> int:
        """
        Calculate packet checksum
        :param packet: Bytes of packet
        :return: Result checksum
        """
        if len(packet) % 2 == 1:
            packet += '\0'
        s = sum(array('H', packet))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s >> 8) & 0xff) | s << 8) & 0xffff

    def parse_packet(self,
                     packet: bytes,
                     exit_on_failure: bool = False,
                     quiet: bool = True):
        """
        Parse ICMPv4 packet
        :param packet: Bytes of packet
        :param exit_on_failure: Exit in case of error (default: False)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Parsed ICMPv4 packet dictionary (example: {}) or None if error
        """
        error_text: str = 'Failed to parse ICMPv4 packet!'
        icmpv4_packet: Dict[str, Union[int, str, bytes]] = dict()
        try:
            assert not len(packet) < RawICMPv4.packet_length, \
                ' Bad packet length: ' + self.base.error_text(str(len(packet))) + \
                ' minimal ICMPv4 packet length: ' + self.base.info_text(str(RawICMPv4.packet_length))

            icmpv4_detailed = unpack('!' '2B' 'H', packet[:4])

            icmpv4_packet['type'] = int(icmpv4_detailed[0])
            icmpv4_packet['code'] = int(icmpv4_detailed[1])
            icmpv4_packet['checksum'] = int(icmpv4_detailed[2])

            # ICMPv4 Echo (ping) request or reply
            if icmpv4_packet['type'] == 0 or icmpv4_packet['type'] == 8:
                icmpv4_detailed = unpack('!' '2H', packet[4:8])
                icmpv4_packet['identifier'] = int(icmpv4_detailed[0])
                icmpv4_packet['sequence_number'] = int(icmpv4_detailed[1])
                # ICMPv4 Echo (ping) reply - add 8 bytes timestamp
                if icmpv4_packet['type'] == 0:
                    icmpv4_detailed = unpack('!' 'Q', packet[8:16])
                    icmpv4_packet['timestamp'] = int(icmpv4_detailed[0])
                    icmpv4_packet['data'] = str(packet[16:])
                # ICMPv4 Echo (ping) request
                if icmpv4_packet['type'] == 8:
                    icmpv4_packet['data'] = str(packet[8:])

            return icmpv4_packet

        except AssertionError as Error:
            error_text += Error.args[0]

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(1)
        return None

    def make_packet(self,
                    ethernet_src_mac: str = '01:23:45:67:89:0a',
                    ethernet_dst_mac: str = '01:23:45:67:89:0b',
                    ip_src: str = '192.168.0.1',
                    ip_dst: str = '192.168.0.2',
                    ip_ident: Union[None, int] = None,
                    icmp_type: int = 1,
                    icmp_code: int = 1,
                    data: Union[None, bytes] = None) -> Union[None, bytes]:
        """
        Make ICMPv4 packet
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param ip_src: Source IPv4 address string in Network header (example: '192.168.0.1')
        :param ip_dst: Destination IPv4 address string in Network header (example: '192.168.0.2')
        :param ip_ident: Identification integer value for IPv4 header (optional value)
        :param icmp_type: ICMPv4 type integer (example: 1)
        :param icmp_code: ICMPv4 code integer (example: 1)
        :param data: Bytes of ICMPv4 data or None (optional value)
        :return: Bytes of ICMPv4 packet or None if error
        """
        error_text: str = 'Failed to make ICMPv4 packet!'
        packet: bytes = b''
        icmp_packet: bytes = b''
        try:
            check_sum: int = 0x0000
            unused: int = 0x00000000

            if icmp_type != 0x05:
                icmp_packet += pack('!' '2B' 'H' 'I', icmp_type, icmp_code, check_sum, unused)
            else:
                icmp_packet += pack('!' '2B' 'H', icmp_type, icmp_code, check_sum)

            if data is not None:
                icmp_packet += data

            check_sum: int = self.checksum(icmp_packet)
            icmp_packet: bytes = b''

            if icmp_type != 0x05:
                icmp_packet += pack('!' '2B' 'H' 'I', icmp_type, icmp_code, check_sum, unused)
            else:
                icmp_packet += pack('!' '2B' 'H', icmp_type, icmp_code, check_sum)

            if data is not None:
                icmp_packet += data

            eth_header = self.eth.make_header(source_mac=ethernet_src_mac,
                                              destination_mac=ethernet_dst_mac,
                                              network_type=self.ip.header_type)

            ip_header = self.ip.make_header(source_ip=ip_src,
                                            destination_ip=ip_dst,
                                            data_len=len(icmp_packet) - 8,
                                            transport_protocol_len=8,
                                            transport_protocol_type=1,
                                            ttl=64,
                                            identification=ip_ident)

            packet += eth_header
            packet += ip_header
            packet += icmp_packet
            return packet

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'eth_header' in traceback_text:
                error_text += ' Bad source or destination MAC address!'
            if 'ip_header' in traceback_text:
                error_text += ' Bad value in IPv4 header!'

        except struct_error:
            error_text += ' Bad ICMPv4 type or ICMPv4 code!'

        self.base.print_error(error_text)
        return None

    def make_host_unreachable_packet(self,
                                     ethernet_src_mac: str = '01:23:45:67:89:0a',
                                     ethernet_dst_mac: str = '01:23:45:67:89:0b',
                                     ip_src: str = '192.168.0.1',
                                     ip_dst: str = '192.168.0.2',
                                     ip_ident: Union[None, int] = None,
                                     data: Union[None, bytes] = None) -> Union[None, bytes]:
        """
        Make ICMPv4 Host Unreachable packet
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param ip_src: Source IPv4 address string in Network header (example: '192.168.0.1')
        :param ip_dst: Destination IPv4 address string in Network header (example: '192.168.0.2')
        :param ip_ident: Identification integer value for IPv4 header (optional value)
        :param data: Bytes of ICMPv4 data or None (optional value)
        :return: Bytes of ICMPv4 Host Unreachable packet or None if error
        """
        error_text: str = 'Failed to make ICMPv4 Host Unreachable packet!'
        icmp_data: bytes = b''
        try:
            if data is not None:
                ip_data = self.ip.make_header(source_ip=ip_dst,
                                              destination_ip=ip_src,
                                              data_len=len(data),
                                              transport_protocol_len=8,
                                              transport_protocol_type=17,
                                              ttl=64,
                                              identification=ip_ident)
                icmp_data += ip_data + data
            else:
                ip_data = self.ip.make_header(source_ip=ip_dst,
                                              destination_ip=ip_src,
                                              data_len=0,
                                              transport_protocol_len=8,
                                              transport_protocol_type=1,
                                              ttl=64,
                                              identification=ip_ident)
                icmp_data += ip_data

            return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                    ethernet_dst_mac=ethernet_dst_mac,
                                    ip_src=ip_src, ip_dst=ip_dst,
                                    ip_ident=ip_ident, icmp_type=0x03,
                                    icmp_code=0x01, data=icmp_data)
        except TypeError:
            error_text += ' Bad value in IPv4 header!'

        self.base.print_error(error_text)
        return None

    def make_udp_port_unreachable_packet(self,
                                         ethernet_src_mac: str = '01:23:45:67:89:0a',
                                         ethernet_dst_mac: str = '01:23:45:67:89:0b',
                                         ip_src: str = '192.168.0.1',
                                         ip_dst: str = '192.168.0.2',
                                         ip_ident: Union[None, int] = None,
                                         udp_src_port: int = 53,
                                         udp_dst_port: int = 53,
                                         data: Union[None, bytes] = None) -> Union[None, bytes]:
        """
        Make ICMPv4 UDP Port Unreachable packet
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param ip_src: Source IPv4 address string in Network header (example: '192.168.0.1')
        :param ip_dst: Destination IPv4 address string in Network header (example: '192.168.0.2')
        :param ip_ident: Identification integer value for IPv4 header (optional value)
        :param udp_src_port: UDP source port (example: 53)
        :param udp_dst_port: UDP destination port (example: 53)
        :param data: Bytes of ICMPv4 data or None (optional value)
        :return: Bytes of ICMPv4 UDP Port Unreachable packet or None if error
        """
        error_text: str = 'Failed to make ICMPv4 UDP Port Unreachable packet!'
        icmp_data: bytes = b''
        try:
            if data is not None:
                udp_data = self.udp.make_header(source_port=udp_src_port,
                                                destination_port=udp_dst_port,
                                                data_length=len(data))
                ip_data = self.ip.make_header(source_ip=ip_dst,
                                              destination_ip=ip_src,
                                              data_len=self.udp.header_length + len(data),
                                              transport_protocol_len=self.udp.header_length,
                                              transport_protocol_type=self.udp.header_type,
                                              ttl=64,
                                              identification=ip_ident)
                icmp_data += ip_data
                icmp_data += udp_data
                icmp_data += data
            else:
                udp_data = self.udp.make_header(source_port=udp_src_port,
                                                destination_port=udp_dst_port,
                                                data_length=0)
                ip_data = self.ip.make_header(source_ip=ip_dst,
                                              destination_ip=ip_src,
                                              data_len=self.udp.header_length,
                                              transport_protocol_len=self.udp.header_length,
                                              transport_protocol_type=self.udp.header_type,
                                              ttl=64,
                                              identification=ip_ident)
                icmp_data += ip_data
                icmp_data += udp_data

            return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                    ethernet_dst_mac=ethernet_dst_mac,
                                    ip_src=ip_src, ip_dst=ip_dst,
                                    ip_ident=ip_ident, icmp_type=0x03,
                                    icmp_code=0x03, data=icmp_data)
        except TypeError:
            pass

        self.base.print_error(error_text)
        return None

    def make_ping_request_packet(self,
                                 ethernet_src_mac: str = '01:23:45:67:89:0a',
                                 ethernet_dst_mac: str = '01:23:45:67:89:0b',
                                 ip_src: str = '192.168.0.1',
                                 ip_dst: str = '192.168.0.2',
                                 ip_ident: Union[None, int] = None,
                                 data: Union[None, bytes] = None) -> Union[None, bytes]:
        """
        Make ICMPv4 Ping Request packet
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param ip_src: Source IPv4 address string in Network header (example: '192.168.0.1')
        :param ip_dst: Destination IPv4 address string in Network header (example: '192.168.0.2')
        :param ip_ident: Identification integer value for IPv4 header (optional value)
        :param data: Bytes of ICMPv4 data or None (optional value)
        :return: Bytes of ICMPv4 Ping Request packet or None if error
        """
        if data is None:
            icmp_data = pack('!Q', int(time()))
            for index in range(0, 32, 1):
                icmp_data += pack('B', index)
        else:
            icmp_data = data

        return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                ethernet_dst_mac=ethernet_dst_mac,
                                ip_src=ip_src, ip_dst=ip_dst,
                                ip_ident=ip_ident, icmp_type=0x08,
                                icmp_code=0x00, data=icmp_data)

    def make_redirect_packet(self,
                             ethernet_src_mac: str = '01:23:45:67:89:0a',
                             ethernet_dst_mac: str = '01:23:45:67:89:0b',
                             ip_src: str = '192.168.0.1',
                             ip_dst: str = '192.168.0.2',
                             ip_ttl: int = 64,
                             ip_ident: Union[None, int] = None,
                             gateway_address: str = '192.168.0.1',
                             payload_ip_src: str = '192.168.0.2',
                             payload_ip_dst: str = '192.168.0.3',
                             payload_port_src=53,
                             payload_port_dst=53) -> Union[None, bytes]:
        """
        Make ICMPv4 Redirect packet
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param ip_src: Source IPv4 address string in Network header (example: '192.168.0.1')
        :param ip_dst: Destination IPv4 address string in Network header (example: '192.168.0.2')
        :param ip_ident: Identification integer value for IPv4 header (optional value)
        :param ip_ttl: TTL for IPv4 header (default: 64)
        :param gateway_address: IPv4 address of Gateway (example: '192.168.0.1')
        :param payload_ip_src: Source IPv4 address in ICMPv4 payload - client IPv4 address (example: '192.168.0.2')
        :param payload_ip_dst: Destination IPv4 address in ICMPv4 payload - server IPv4 address (example: '192.168.0.3')
        :param payload_port_src: Source port in ICMPv4 payload - client port (example: '53')
        :param payload_port_dst: Destination port in ICMPv4 payload - server port (example: '53')
        :return: Bytes of ICMPv4 Redirect packet or None if error
        """
        error_text: str = 'Failed to make ICMPv4 Redirect packet!'
        icmp_data: bytes = b''
        try:
            ip_data: Union[None, bytes] = self.ip.make_header(source_ip=payload_ip_src,
                                                              destination_ip=payload_ip_dst,
                                                              data_len=0,
                                                              transport_protocol_len=self.udp.header_length,
                                                              transport_protocol_type=self.udp.header_type,
                                                              ttl=ip_ttl,
                                                              identification=ip_ident)
            udp_data: Union[None, bytes] = self.udp.make_header(source_port=payload_port_src,
                                                                destination_port=payload_port_dst,
                                                                data_length=0)
            icmp_data += inet_aton(gateway_address)
            icmp_data += ip_data
            icmp_data += udp_data
            return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                    ethernet_dst_mac=ethernet_dst_mac,
                                    ip_src=ip_src, ip_dst=ip_dst,
                                    ip_ident=ip_ident, icmp_type=0x05,
                                    icmp_code=0x01, data=icmp_data)
        except OSError:
            error_text += ' Bad gateway IPv4 address: ' + self.base.error_text(str(gateway_address))

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'udp_data' in traceback_text:
                error_text += ' Bad source or destination UDP port!'
            if 'ip_data' in traceback_text:
                error_text += ' Bad value in IPv4 header!'

        self.base.print_error(error_text)
        return None

# endregion


# region Raw DHCPv6
class RawDHCPv6:
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |   Message   |                   Data :::                      |
    # +-------------+-------------------------------------------------+

    # DHCPv6 Message Types
    # 0	    Reserved
    # 1	    SOLICIT	            [RFC3315]
    # 2	    ADVERTISE	        [RFC3315]
    # 3	    REQUEST	            [RFC3315]
    # 4	    CONFIRM	            [RFC3315]
    # 5	    RENEW	            [RFC3315]
    # 6	    REBIND	            [RFC3315]
    # 7	    REPLY	            [RFC3315]
    # 8	    RELEASE	            [RFC3315]
    # 9	    DECLINE	            [RFC3315]
    # 10	RECONFIGURE	        [RFC3315]
    # 11	INFORMATION-REQUEST	[RFC3315]
    # 12	RELAY-FORW	        [RFC3315]
    # 13	RELAY-REPL	        [RFC3315]
    # 14	LEASEQUERY	        [RFC5007]
    # 15	LEASEQUERY-REPLY	[RFC5007]
    # 16	LEASEQUERY-DONE	    [RFC5460]
    # 17	LEASEQUERY-DATA	    [RFC5460]
    # 18	RECONFIGURE-REQUEST [RFC6977]
    # 19	RECONFIGURE-REPLY	[RFC6977]
    # 20	DHCPV4-QUERY	    [RFC7341]
    # 21	DHCPV4-RESPONSE	    [RFC7341]
    # 22	ACTIVELEASEQUERY	[RFC7653]
    # 23	STARTTLS	        [RFC7653]
    # 24	BNDUPD	            [RFC8156]
    # 25	BNDREPLY	        [RFC8156]
    # 26	POOLREQ	            [RFC8156]
    # 27	POOLRESP	        [RFC8156]
    # 28	UPDREQ	            [RFC8156]
    # 29	UPDREQALL	        [RFC8156]
    # 30	UPDDONE	            [RFC8156]
    # 31	CONNECT	            [RFC8156]
    # 32	CONNECTREPLY	    [RFC8156]
    # 33	DISCONNECT	        [RFC8156]
    # 34	STATE	            [RFC8156]
    # 35	CONTACT	            [RFC8156]
    # 36-255	Unassigned

    # region Properties
    base: Base = Base()
    eth: RawEthernet = RawEthernet()
    ipv6: RawIPv6 = RawIPv6()
    udp: RawUDP = RawUDP()
    dns: RawDNS = RawDNS()
    # endregion

    def _make_duid(self,
                   mac_address: str = '01:23:45:67:89:0a',
                   timeval: Union[None, int] = None) -> Union[None, bytes]:
        error_text: str = 'Failed to make DHCPv6 DUID!'
        hardware_type: int = 1  # Ethernet
        try:
            if timeval is None:
                duid_type: int = 3   # Link-Layer address
                return pack('!' '2H', duid_type, hardware_type) + self.eth.convert_mac(mac_address)
            else:
                duid_type: int = 1   # Link-Layer address plus time
                return pack('!' '2H' 'I', duid_type, hardware_type, timeval) + self.eth.convert_mac(mac_address)

        except TypeError:
            error_text += ' Bad MAC address: ' + self.base.error_text(str(mac_address))

        except struct_error:
            error_text += ' Bad timeval: ' + self.base.error_text(str(timeval))

        self.base.print_error(error_text)
        return None

    def make_packet(self, ethernet_src_mac: str = '01:23:45:67:89:0a',
                    ethernet_dst_mac: str = '01:23:45:67:89:0b',
                    ipv6_src: str = 'fd00::1',
                    ipv6_dst: str = 'fd00::2',
                    ipv6_flow: int = 1,
                    udp_src_port: int = 546,
                    udp_dst_port: int = 547,
                    dhcp_message_type: int = 1,
                    packet_body: bytes = b'',
                    options: Union[None, Dict[int, bytes]] = {14: b''},
                    options_raw: Union[None, bytes] = None) -> Union[None, bytes]:
        error_text: str = 'Failed to make DHCPv6 packet!'
        packet: bytes = b''
        dhcp_packet: bytes = b''
        try:
            dhcp_packet += pack('!B', dhcp_message_type)
            dhcp_packet += packet_body

            if options is not None:
                for option_code in options.keys():
                    dhcp_packet += pack('!' '2H', int(option_code), len(options[option_code]))
                    dhcp_packet += options[option_code]

            if options_raw is not None:
                dhcp_packet += options_raw

            eth_header = self.eth.make_header(source_mac=ethernet_src_mac,
                                              destination_mac=ethernet_dst_mac,
                                              network_type=self.ipv6.header_type)  # 34525 = 0x86dd (IPv6)

            ipv6_header = self.ipv6.make_header(source_ip=ipv6_src,
                                                destination_ip=ipv6_dst,
                                                flow_label=ipv6_flow,
                                                payload_len=len(dhcp_packet) + self.udp.header_length,
                                                next_header=self.udp.header_type)  # 17 = 0x11 (UDP)

            udp_header = self.udp.make_header_with_ipv6_checksum(ipv6_src=ipv6_src,
                                                                 ipv6_dst=ipv6_dst,
                                                                 port_src=udp_src_port,
                                                                 port_dst=udp_dst_port,
                                                                 payload_len=len(dhcp_packet),
                                                                 payload_data=dhcp_packet)
            packet += eth_header
            packet += ipv6_header
            packet += udp_header
            packet += dhcp_packet
            return packet

        except TypeError as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'eth_header' in traceback_text:
                error_text += ' Bad source or destination MAC address!'
            if 'ipv6_header' in traceback_text:
                error_text += ' Bad value in IPv6 header!'
            if 'udp_header' in traceback_text:
                error_text += ' Bad value in UDP header!'

        except struct_error as Error:
            traceback_text: str = format_tb(Error.__traceback__)[0]
            if 'dhcp_message_type' in traceback_text:
                error_text += ' Bad DHCPv6 message type: ' + self.base.error_text(str(dhcp_message_type))
            if 'option_code' in traceback_text:
                error_text += ' Bad DHCPv6 option code or option value!'

        self.base.print_error(error_text)
        return None

    def parse_packet(self, packet: bytes):
        if len(packet) < 4:
            return None

        offset = 4

        type_and_id = int(unpack('!L', packet[:offset])[0])
        message_type = int(int(type_and_id & 0b11111111000000000000000000000000) >> 24)
        transaction_id = int(type_and_id & 0b00000000111111111111111111111111)

        dhcpv6_packet = {
            'message-type':   message_type,
            'transaction-id': transaction_id
        }

        options = []

        while offset < len(packet):
            option_type = int(unpack('!H', packet[offset:offset + 2])[0])
            option_length = int(unpack('!H', packet[offset + 2:offset + 4])[0])
            offset += 4

            if option_type == 1:
                option_detailed = unpack('!' '2H' 'L' '6s', packet[offset:offset + 14])
                option_value = {
                    'duid-type': int(option_detailed[0]),
                    'hardware-type': int(option_detailed[1]),
                    'duid-time': int(option_detailed[2]),
                    'mac-address': self.eth.convert_mac(option_detailed[3]),
                    'raw': packet[offset:offset+option_length]
                }

            elif option_type == 2:
                option_detailed = unpack('!' '2H' '6s', packet[offset:offset + 10])
                option_value = {
                    'duid-type': int(option_detailed[0]),
                    'duid-time': int(option_detailed[1]),
                    'mac-address': self.eth.convert_mac(option_detailed[2]),
                    'raw': packet[offset:offset+option_length]
                }

            elif option_type == 3:
                iaid = unpack('!' 'L', packet[offset:offset + 4])[0]
                if option_length >= 40:
                    ipv6_addr = unpack('!' '16s', packet[offset + 16:offset + 32])[0]
                    ipv6_addr = inet_ntop(AF_INET6, ipv6_addr)
                else:
                    ipv6_addr = None
                option_value = {
                    'iaid': int(iaid),
                    'ipv6-address': ipv6_addr
                }

            elif option_type == 8:
                option_detailed = unpack('!H', packet[offset:offset + 2])
                option_value = {
                    'elapsed-time': int(option_detailed[0]),
                }

            else:
                option_value = packet[offset:offset + option_length]

            offset += option_length

            options.append({
                'type': option_type,
                'value': option_value
            })

        dhcpv6_packet['options'] = options

        return dhcpv6_packet

    def make_solicit_packet(self,
                            ethernet_src_mac: str = '01:23:45:67:89:0a',
                            ipv6_src: str = 'fd00::1',
                            transaction_id: int = 1,
                            client_mac_address: str = '01:23:45:67:89:0a',
                            option_request_list: List[int] = [23, 24]):

        if 16777215 < transaction_id < 0:
            return None

        packet_body = pack('!L', transaction_id)[1:]
        options: Dict[int, bytes] = dict()
        options[3] = pack('!' '3Q', 0, 0, 0)              # Identity Association for Non-temporary Address
        options[14] = b''                                 # Rapid commit
        options[8] = pack('!H', 0)                        # Elapsed time
        options[1] = self._make_duid(client_mac_address)  # Client identifier

        option_request_string = b''
        for option_request in option_request_list:
            option_request_string += pack('!H', option_request)

        options[6] = option_request_string  # Options request

        return self.make_packet(ethernet_src_mac, '33:33:00:01:00:02',
                                ipv6_src, 'ff02::1:2', 0, 546, 547,
                                1, packet_body, options)

    def make_relay_forw_packet(self,
                               ethernet_src_mac: str = '01:23:45:67:89:0a',
                               ethernet_dst_mac: str = '01:23:45:67:89:0b',
                               ipv6_src: str = 'fd00::1',
                               ipv6_dst: str = 'fd00::2',
                               ipv6_flow: int = 1,
                               hop_count: int = 10,
                               link_addr: str = 'fd00::1',
                               peer_addr: str = 'fd00::2',
                               options: Union[None, Dict[int, bytes]] = None,
                               options_raw: Union[None, bytes] = None):
        error_text: str = 'Failed to make DHCPv6 Relay-forw packet!'
        try:
            assert hop_count <= 32, ' Maximum hop count limit = 32'
            packet_body = pack('!B', hop_count) + self.ipv6.pack_addr(link_addr) + self.ipv6.pack_addr(peer_addr)
            return self.make_packet(ethernet_src_mac, ethernet_dst_mac,
                                    ipv6_src, ipv6_dst, ipv6_flow, 546, 547,
                                    12, packet_body, options, options_raw)
        except AssertionError as Error:
            error_text += Error.args[0]

        self.base.print_error(error_text)
        return None

    def make_advertise_packet(self,
                              ethernet_src_mac: str = '01:23:45:67:89:0a',
                              ethernet_dst_mac: str = '01:23:45:67:89:0b',
                              ipv6_src: str = 'fd00::1',
                              ipv6_dst: str = 'fd00::2',
                              transaction_id: int = 1,
                              dns_address: str = 'fd00::1',
                              domain_search: str = 'domain.local',
                              ipv6_address: str = 'fd00::2',
                              client_duid_timeval: Union[None, int] = None,
                              server_duid_mac: Union[None, str] = None,
                              cid: Union[None, bytes] = None,
                              iaid: int = 1,
                              preference: Union[None, int] = None):

        if 16777215 < transaction_id < 0:
            return None

        packet_body = pack('!L', transaction_id)[1:]
        options: Dict[int, bytes] = dict()

        if cid is not None:
                options[1] = cid
        else:
            if client_duid_timeval is None:
                    options[1] = self._make_duid(ethernet_dst_mac)                   # Client Identifier
            else:
                options[1] = self._make_duid(ethernet_dst_mac, client_duid_timeval)  # Client Identifier

        if server_duid_mac is None:
            options[2] = self._make_duid(ethernet_src_mac)  # Server Identifier
        else:
            options[2] = self._make_duid(server_duid_mac)   # Server Identifier

        if preference is not None:
            options[7] = pack('!B', preference)

        options[20] = b''                                    # Reconfigure Accept
        options[23] = self.ipv6.pack_addr(dns_address)       # DNS recursive name server
        options[24] = self.dns.pack_dns_name(domain_search)  # Domain search list
        options[82] = pack('!I', 0x3c)                       # SOL_MAX_RT

        options[3] = pack('!' '3I' '2H', iaid, 21600, 34560, 5, 24) + self.ipv6.pack_addr(ipv6_address) + \
                     pack('!2I', 0xffffffff, 0xffffffff)     # Identity Association for Non-temporary address

        return self.make_packet(ethernet_src_mac, ethernet_dst_mac,
                                ipv6_src, ipv6_dst,
                                0xa1b82, 547, 546, 2,
                                packet_body, options)

    def make_reply_packet(self,
                          ethernet_src_mac: str = '01:23:45:67:89:0a',
                          ethernet_dst_mac: str = '01:23:45:67:89:0b',
                          ipv6_src: str = 'fd00::1',
                          ipv6_dst: str = 'fd00::2',
                          transaction_id: int = 1,
                          dns_address: str = 'fd00::1',
                          domain_search: str = 'domain.local',
                          ipv6_address: str = 'fd00::2',
                          client_duid_timeval: Union[None, int] = None,
                          server_duid_mac: Union[None, str] = None):

        if 16777215 < transaction_id < 0:
            return None

        packet_body = pack('!L', transaction_id)[1:]
        options = {}

        if client_duid_timeval is None:
            options[1] = self._make_duid(ethernet_dst_mac)                       # Client Identifier
        else:
            options[1] = self._make_duid(ethernet_dst_mac, client_duid_timeval)  # Client Identifier

        if server_duid_mac is None:
            options[2] = self._make_duid(ethernet_src_mac)  # Server Identifier
        else:
            options[2] = self._make_duid(server_duid_mac)   # Server Identifier

        options[20] = b''                                    # Reconfigure Accept
        options[23] = self.ipv6.pack_addr(dns_address)       # DNS recursive name server
        options[24] = self.dns.pack_dns_name(domain_search)  # Domain search list
        options[82] = pack('!I', 0x3c)                       # SOL_MAX_RT

        options[3] = pack('!' '3I' '2H', 1, 21600, 34560, 5, 24) + self.ipv6.pack_addr(ipv6_address) + \
                     pack('!2I', 0xffffffff, 0xffffffff)     # Identity Association for Non-temporary address

        return self.make_packet(ethernet_src_mac, ethernet_dst_mac,
                                ipv6_src, ipv6_dst,
                                0xa1b82, 547, 546, 7,
                                packet_body, options)

    # def make_reconfigure_packet(self, ethernet_src_mac, ethernet_dst_mac,
    #                             ipv6_src, ipv6_dst, transaction_id, dns_address,
    #                             domain_search, ipv6_address):
    #     if 16777215 < transaction_id < 0:
    #         return None
    #
    #     packet_body = pack('!L', transaction_id)[1:]
    #     options = {}
    #
    #     options[1] = self._make_duid(ethernet_dst_mac)                       # Client Identifier
    #     options[2] = self._make_duid(ethernet_src_mac)  # Server Identifier
    #
    #     options[20] = ''                                     # Reconfigure Accept
    #     options[23] = self.ipv6.pack_addr(dns_address)       # DNS recursive name server
    #     options[24] = self.dns.pack_dns_name(domain_search)  # Domain search list
    #     options[82] = pack('!I', 0x3c)                       # SOL_MAX_RT
    #
    #     options[3] = pack('!' '3I' '2H', 1, 21600, 34560, 5, 24) + self.ipv6.pack_addr(ipv6_address) + \
    #                  pack('!2I', 0xffffffff, 0xffffffff)     # Identity Association for Non-temporary address
    #
    #     return self.make_packet(ethernet_src_mac, ethernet_dst_mac,
    #                             ipv6_src, ipv6_dst,
    #                             0xa1b82, 547, 546, 10,
    #                             packet_body, options)
# endregion


# region Raw ICMPv6
class RawICMPv6:
    """
    Class for making and parsing ICMPv6 packet
    """
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     Type      |     Code      |          Checksum             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                               |
    # +                         Message Body                          +
    # |                                                               |

    # region Properties

    # Set Packet type
    packet_type: int = 58

    # Set Packet minimal length
    packet_length: int = 4

    # Init Raw Ethernet
    eth: RawEthernet = RawEthernet()

    # Init Raw IPv6
    ipv6: RawIPv6 = RawIPv6()

    # Init Raw DNS
    dns: RawDNS = RawDNS()

    # Init Raw-packet Base class
    base: Base = Base()
    
    # Init ICMPv6 types
    types: Dict[str, int] = dict()

    # endregion
    
    def __init__(self) -> None:
        self.types['Echo (ping) request'] = 128
        self.types['Echo (ping) reply'] = 129
        self.types['Router Solicitation'] = 133
        self.types['Router Advertisement'] = 134
        self.types['Neighbor Solicitation'] = 135
        self.types['Neighbor Advertisement'] = 136
        self.types['Multicast listener report'] = 143

    @staticmethod
    def checksum(packet: bytes) -> int:
        """
        Calculate packet checksum
        :param packet: Bytes of packet
        :return: Result checksum
        """
        if len(packet) % 2 == 1:
            packet += '\0'
        s = sum(array('H', packet))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s >> 8) & 0xff) | s << 8) & 0xffff

    def make_option(self,
                    option_type: int = 1,
                    option_value: bytes = b'',
                    exit_on_failure: bool = True,
                    exit_code: int = 44,
                    quiet: bool = False) -> Union[None, bytes]:
        """
        Make ICMPv6 option to bytes
        :param option_type: Set ICMPv6 option type integer (example: 1)
        :param option_value: Set ICMPv6 option value bytes (example: b'')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 44)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of ICMPv6 option
        """
        try:
            assert not (len(option_value) + 2) / 8 > 255, \
                'ICMPv6 option value too big!' + \
                ' Option type: ' + self.base.error_text(str(option_type)) + \
                ' option value: ' + self.base.error_text(str(option_value))
            if (len(option_value) + 2) % 8 != 0:
                option_value = b''.join(pack('B', 0) for _ in range(8 - ((len(option_value) + 2) % 8))) + option_value
            return pack('!2B', option_type, int((len(option_value) + 2) / 8)) + option_value

        except AssertionError as Error:
            error_text = Error.args[0]

        except struct_error:
            error_text = 'Failed to make IPCMv6 option!' + \
                         ' Option type: ' + self.base.error_text(str(option_type)) + \
                         ' option value: ' + self.base.error_text(str(option_value))

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def parse_packet(self,
                     packet: bytes,
                     exit_on_failure: bool = False,
                     exit_code: int = 45,
                     quiet: bool = True) -> Union[None, Dict[str, Union[int, str, Dict[str, Union[int, str]]]]]:
        """
        Parse IMCPv6 packet
        :param packet: Bytes of packet
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 45)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Parsed ICMPv6 header dictionary (example: {}) or None if error
        """
        try:
            assert len(packet) > self.packet_length, \
                'Bad packet length: ' + self.base.error_text(str(len(packet))) + \
                ' minimal ICMPv6 packet length: ' + self.base.info_text(str(self.packet_length))

            offset = self.packet_length

            icmpv6_detailed = unpack('!' '2B' 'H', packet[:self.packet_length])

            icmpv6_packet = {
                'type': int(icmpv6_detailed[0]),
                'code': int(icmpv6_detailed[1]),
                'checksum': int(icmpv6_detailed[2]),
            }

            # Type: 128 is Echo (ping) request, 129 is Echo (ping) reply
            if icmpv6_packet['type'] == self.types['Echo (ping) request'] or \
                    icmpv6_packet['type'] == self.types['Echo (ping) reply']:
                icmpv6_ping_detailed = unpack('!2H', packet[offset:offset + 4])
                icmpv6_packet['identifier'] = int(icmpv6_ping_detailed[0])
                icmpv6_packet['sequence'] = int(icmpv6_ping_detailed[1])
                return icmpv6_packet

            if len(packet) <= offset + 4:
                return icmpv6_packet

            # 133 - Router Solicitation
            if icmpv6_packet['type'] == self.types['Router Solicitation']:
                return icmpv6_packet

            # 134 - Router Advertisement
            elif icmpv6_packet['type'] == self.types['Router Advertisement']:
                icmpv6_packet['hop-limit'] = int(unpack('B', packet[offset:offset + 1])[0])
                icmpv6_packet['flags'] = int(unpack('B', packet[offset + 1:offset + 2])[0])
                icmpv6_packet['router-lifetime'] = int(unpack('!H', packet[offset + 2:offset + 4])[0])
                icmpv6_packet['reachable-time'] = int(unpack('!I', packet[offset + 4:offset + 8])[0])
                icmpv6_packet['retrans-timer'] = int(unpack('!I', packet[offset + 8:offset + 12])[0])
                offset += 12

            # 135 - Neighbor Solicitation
            elif icmpv6_packet['type'] == self.types['Neighbor Solicitation']:
                target_address = unpack('!16s', packet[offset + 4:offset + 20])[0]
                try:
                    icmpv6_packet['target-address'] = inet_ntop(AF_INET6, target_address)
                except sock_error:
                    icmpv6_packet['target-address'] = None
                return icmpv6_packet

            # Analyze ICMPv6 options for Router Advertisement packet
            if icmpv6_packet['type'] == self.types['Router Advertisement']:
                options = []

                while offset < len(packet):
                    option_type = int(unpack('B', packet[offset:offset + 1])[0])
                    option_length = int(unpack('B', packet[offset + 1:offset + 2])[0])

                    if option_type == 1:
                        option_value = self.eth.convert_mac(packet[offset + 2:offset + 8])

                    elif option_type == 3:
                        option_detailed = unpack('!' '2B' '3I' '16s', packet[offset + 2:offset + 32])
                        option_value = {
                            'prefix-length': int(option_detailed[0]),
                            'flag': int(option_detailed[1]),
                            'valid-lifetime': int(option_detailed[2]),
                            'reserved-lifetime': int(option_detailed[3]),
                            'prefix': inet_ntop(AF_INET6, option_detailed[5])
                        }

                    elif option_type == 25:
                        option_detailed = unpack('!' 'H' 'I' '16s', packet[offset + 2:offset + 24])
                        option_value = {
                            'lifetime': int(option_detailed[1]),
                            'address': inet_ntop(AF_INET6, option_detailed[2])
                        }

                    else:
                        option_value = hexlify(packet[offset + 2:offset + option_length * 8])

                    offset += option_length * 8

                    options.append({
                        'type': option_type,
                        'value': option_value
                    })

                icmpv6_packet['options'] = options
                return icmpv6_packet

            else:
                return icmpv6_packet

        except AssertionError as Error:
            error_text = Error.args[0]

        except IndexError:
            error_text = 'Failed to parse ICMPv6 packet!'

        except struct_error:
            error_text = 'Failed to parse ICMPv6 packet!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_packet(self,
                    ethernet_src_mac: str = '01:23:45:67:89:0a',
                    ethernet_dst_mac: str = '01:23:45:67:89:0b',
                    ipv6_src: str = 'fd00::1',
                    ipv6_dst: str = 'fd00::2',
                    ipv6_flow: int = 0,
                    ipv6_hop_limit: int = 255,
                    icmpv6_type: int = 0,
                    icmpv6_code: int = 0,
                    icmpv6_body: bytes = b'',
                    exit_on_failure: bool = True,
                    exit_code: int = 46,
                    quiet: bool = False) -> Union[None, bytes]:
        """
        Make ICMPv6 packet
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param ipv6_src: Source IPv6 address string in IPv6 header (example: 'fd00::1')
        :param ipv6_dst: Destination IPv6 address string in IPv6 header (example: 'fd00::1')
        :param ipv6_flow: IPv6 flow label integer in IPv6 header (default: 0)
        :param ipv6_hop_limit: IPv6 hop limit integer in IPv6 header (default: 255)
        :param icmpv6_type: ICMPv6 type integer (default: 0)
        :param icmpv6_code: ICMPv6 code integer (default: 0)
        :param icmpv6_body: ICMPv6 body bytes (default: b'')
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 46)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of ICMPv6 packet or None if error
        """
        try:
            placeholder = 0
            protocol = IPPROTO_ICMPV6
            check_sum = 0
            icmpv6_packet = pack('!' '2B' 'H', icmpv6_type, icmpv6_code, check_sum) + icmpv6_body
    
            psh = self.ipv6.pack_addr(ipv6_address=ipv6_src,
                                      exit_on_failure=exit_on_failure,
                                      exit_code=exit_code,
                                      quiet=quiet)
            psh += self.ipv6.pack_addr(ipv6_address=ipv6_dst,
                                       exit_on_failure=exit_on_failure,
                                       exit_code=exit_code,
                                       quiet=quiet)
            psh += pack('!' '2B' 'H', placeholder, protocol, len(icmpv6_packet))
            check_sum = self.checksum(psh + icmpv6_packet)
    
            icmpv6_packet = pack('!' '2B' 'H', icmpv6_type, icmpv6_code, check_sum) + icmpv6_body
    
            eth_header = self.eth.make_header(source_mac=ethernet_src_mac,
                                              destination_mac=ethernet_dst_mac,
                                              network_type=self.ipv6.header_type,
                                              exit_on_failure=exit_on_failure,
                                              exit_code=exit_code,
                                              quiet=quiet)
    
            ipv6_header = self.ipv6.make_header(source_ip=ipv6_src,
                                                destination_ip=ipv6_dst,
                                                flow_label=ipv6_flow,
                                                payload_len=len(icmpv6_packet),
                                                next_header=self.packet_type,
                                                hop_limit=ipv6_hop_limit,
                                                exit_on_failure=exit_on_failure,
                                                exit_code=exit_code,
                                                quiet=quiet)
    
            return eth_header + ipv6_header + icmpv6_packet

        except TypeError:
            error_text = 'Failed to make IPCMv6 packet!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_router_solicit_packet(self, 
                                   ethernet_src_mac: str = '01:23:45:67:89:0a', 
                                   ethernet_dst_mac: str = '33:33:00:00:00:02',
                                   ipv6_src: str = 'fd00::1', 
                                   ipv6_dst: str = 'ff02::2',
                                   ipv6_flow=0x835d1,
                                   need_source_link_layer_address: bool = False,
                                   source_link_layer_address: Union[None, str] = None,
                                   exit_on_failure: bool = True,
                                   exit_code: int = 47,
                                   quiet: bool = False) -> Union[None, bytes]:
        """
        Make ICMPv6 Router Solicitation packet
        :param ethernet_src_mac: Source MAC address string in Ethernet header (example: '01:23:45:67:89:0a')
        :param ethernet_dst_mac: Destination MAC address string in Ethernet header (example: '01:23:45:67:89:0b')
        :param ipv6_src: Source IPv6 address string in IPv6 header (example: 'fd00::1')
        :param ipv6_dst: Destination IPv6 address string in IPv6 header (example: 'fd00::1')
        :param ipv6_flow: IPv6 flow label integer in IPv6 header (default: 0)
        :param need_source_link_layer_address: 
        :param source_link_layer_address: 
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 47)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: Bytes of ICMPv6 Router Solicitation packet or None if error
        """
        try:
            body = pack('I', 0)     # 4 reserved bytes
            if need_source_link_layer_address:
                body += pack('!' '2B', 1, 1)    # 1 - Type: source link address, 1 - Length = 1 (8 bytes)
    
                if source_link_layer_address is None:
                    body += self.eth.convert_mac(mac_address=ethernet_src_mac,
                                                 exit_on_failure=exit_on_failure,
                                                 exit_code=exit_code,
                                                 quiet=quiet)
                else:
                    body += self.eth.convert_mac(mac_address=source_link_layer_address,
                                                 exit_on_failure=exit_on_failure,
                                                 exit_code=exit_code,
                                                 quiet=quiet)
    
            return self.make_packet(ethernet_src_mac=ethernet_src_mac, 
                                    ethernet_dst_mac=ethernet_dst_mac, 
                                    ipv6_src=ipv6_src, 
                                    ipv6_dst=ipv6_dst, 
                                    ipv6_flow=ipv6_flow, 
                                    icmpv6_type=self.types['Router Solicitation'], 
                                    icmpv6_code=0, 
                                    icmpv6_body=body)

        except TypeError:
            error_text = 'Failed to make IPCMv6 Router Solicitation packet!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_router_advertisement_packet(self, 
                                         ethernet_src_mac: str = '01:23:45:67:89:0a', 
                                         ethernet_dst_mac: str = '01:23:45:67:89:0b', 
                                         ipv6_src: str = 'fd00::1', 
                                         ipv6_dst: str = 'fd00::2',
                                         dns_address: str = 'fd00::1', 
                                         domain_search: str = 'domain.local', 
                                         prefix: Union[None, str] = None, 
                                         ipv6_addr: Union[None, str] = None, 
                                         mtu: int = 1500,
                                         advertisement_interval: int = 60000, 
                                         src_link_layer_address: Union[None, str] = None,
                                         router_lifetime: int = 0,
                                         reachable_time: int = 0, 
                                         retrans_timer: int = 0,
                                         exit_on_failure: bool = True,
                                         exit_code: int = 48,
                                         quiet: bool = False) -> Union[None, bytes]:
        """
        Make ICMPv6 Router Advertisement packet
        :param ethernet_src_mac: 
        :param ethernet_dst_mac: 
        :param ipv6_src: 
        :param ipv6_dst: 
        :param dns_address: 
        :param domain_search: 
        :param prefix: 
        :param ipv6_addr: 
        :param mtu: 
        :param advertisement_interval: 
        :param src_link_layer_address: 
        :param router_lifetime: 
        :param reachable_time: 
        :param retrans_timer: 
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 48)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: 
        """
        try:
            cur_hop_limit = 64  # Cur hop limit
            flags = 0xc0        # Managed address configuration, other configuration, PRF: Medium
    
            body = pack('!' '2B' 'H' '2I', cur_hop_limit, flags, router_lifetime, reachable_time, retrans_timer)
    
            if src_link_layer_address is None:
                src_link_layer_address = ethernet_src_mac
    
            if prefix is not None:
                prefix_value = self.ipv6.pack_addr(ipv6_address=str(prefix.split('/')[0]),
                                                   exit_on_failure=exit_on_failure,
                                                   exit_code=exit_code,
                                                   quiet=quiet)
                prefix_len = int(prefix.split('/')[1])
                body += self.make_option(option_type=3, 
                                         option_value=pack('!' '2B' '3I', 
                                                           prefix_len, 0xc0, 0xffffffff, 0xffffffff, 0) + prefix_value,
                                         exit_on_failure=exit_on_failure,
                                         exit_code=exit_code,
                                         quiet=quiet)
                if ipv6_addr is not None:
                    body += self.make_option(option_type=17, 
                                             option_value=pack('!' '2B' 'I', 3, prefix_len, 0) + 
                                                          self.ipv6.pack_addr(ipv6_addr),
                                             exit_on_failure=exit_on_failure,
                                             exit_code=exit_code,
                                             quiet=quiet)

            body += self.make_option(option_type=1,
                                     option_value=self.eth.convert_mac(src_link_layer_address),
                                     exit_on_failure=exit_on_failure,
                                     exit_code=exit_code,
                                     quiet=quiet)
            body += self.make_option(option_type=5,
                                     option_value=pack('!H', mtu),
                                     exit_on_failure=exit_on_failure,
                                     exit_code=exit_code,
                                     quiet=quiet)
            body += self.make_option(option_type=25,
                                     option_value=pack('!H', 6000) + self.ipv6.pack_addr(dns_address),
                                     exit_on_failure=exit_on_failure,
                                     exit_code=exit_code,
                                     quiet=quiet)
    
            assert not len(domain_search) > 22, 'Too big domain search value: ' + self.base.error_text(domain_search)

            domain_search = self.dns.pack_dns_name(name=domain_search)
            padding = 24 - len(domain_search)
            domain_search += b''.join(pack('B', 0) for _ in range(padding))
            
            body += self.make_option(option_type=31, 
                                     option_value=pack('!I', 6000) + domain_search,
                                     exit_on_failure=exit_on_failure,
                                     exit_code=exit_code,
                                     quiet=quiet)
            body += self.make_option(option_type=7, 
                                     option_value=pack('!H', advertisement_interval),
                                     exit_on_failure=exit_on_failure,
                                     exit_code=exit_code,
                                     quiet=quiet)
    
            return self.make_packet(ethernet_src_mac=ethernet_src_mac, 
                                    ethernet_dst_mac=ethernet_dst_mac, 
                                    ipv6_src=ipv6_src, 
                                    ipv6_dst=ipv6_dst, 
                                    ipv6_flow=0xb4755, 
                                    icmpv6_type=self.types['Router Advertisement'], 
                                    icmpv6_code=0, 
                                    icmpv6_body=body)

        except AssertionError as Error:
            error_text = Error.args[0]
            
        except TypeError:
            error_text = 'Failed to make IPCMv6 Router Advertisement packet!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_neighbor_solicitation_packet(self, 
                                          ethernet_src_mac: str = '01:23:45:67:89:0a',
                                          ethernet_dst_mac: Union[None, str] = None,
                                          ipv6_src: str = 'fd00::1',
                                          ipv6_dst: Union[None, str] = None,
                                          icmpv6_target_ipv6_address: Union[None, str] = None,
                                          icmpv6_source_mac_address: Union[None, str] = None,
                                          exit_on_failure: bool = True,
                                          exit_code: int = 49,
                                          quiet: bool = False) -> Union[None, bytes]:
        """
        Make ICMPv6 Neighbor Solicitation packet
        :param ethernet_src_mac: 
        :param ethernet_dst_mac: 
        :param ipv6_src: 
        :param ipv6_dst: 
        :param icmpv6_target_ipv6_address: 
        :param icmpv6_source_mac_address: 
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 49)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: 
        """
        try:
            body = pack('!I', 0x00000000)  # Reserved
    
            if icmpv6_target_ipv6_address is None:
                icmpv6_target_ipv6_address = 'ff02::1'
            body += self.ipv6.pack_addr(ipv6_address=icmpv6_target_ipv6_address, 
                                        exit_on_failure=exit_on_failure,
                                        exit_code=exit_code, 
                                        quiet=quiet)
    
            # Source link-layer address
            if icmpv6_source_mac_address is None:
                icmpv6_source_mac_address = ethernet_src_mac
            body += self.make_option(option_type=2, 
                                     option_value=self.eth.convert_mac(icmpv6_source_mac_address),
                                     exit_on_failure=exit_on_failure,
                                     exit_code=exit_code,
                                     quiet=quiet)  
    
            if ethernet_dst_mac is None:
                ethernet_dst_mac = '33:33:00:00:00:01'
    
            if ipv6_dst is None:
                ipv6_dst = 'ff02::1'
    
            return self.make_packet(ethernet_src_mac=ethernet_src_mac, 
                                    ethernet_dst_mac=ethernet_dst_mac, 
                                    ipv6_src=ipv6_src, 
                                    ipv6_dst=ipv6_dst, 
                                    ipv6_flow=0, 
                                    icmpv6_type=self.types['Neighbor Solicitation'], 
                                    icmpv6_code=0, 
                                    icmpv6_body=body,
                                    exit_on_failure=exit_on_failure, 
                                    exit_code=exit_code, 
                                    quiet=quiet)

        except TypeError:
            error_text = 'Failed to make IPCMv6 Neighbor Solicitation packet!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_neighbor_advertisement_packet(self, 
                                           ethernet_src_mac: str = '01:23:45:67:89:0a',
                                           ethernet_dst_mac: Union[None, str] = None,
                                           ipv6_src: str = 'fd00::1',
                                           ipv6_dst: Union[None, str] = None,
                                           target_ipv6_address: str = 'fd00::2',
                                           flags: int = 0x20000000,
                                           exit_on_failure: bool = True,
                                           exit_code: int = 50,
                                           quiet: bool = False) -> Union[None, bytes]:
        """
        Make ICMPv6 Neighbor Advertisement packet
        :param ethernet_src_mac: 
        :param ethernet_dst_mac: 
        :param ipv6_src: 
        :param ipv6_dst: 
        :param target_ipv6_address: 
        :param flags: 
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 50)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: 
        """
        try:
            body = pack('!I', flags)   # Flags: 0x20000000, Override
            body += self.ipv6.pack_addr(ipv6_address=target_ipv6_address,
                                        exit_on_failure=exit_on_failure,
                                        exit_code=exit_code,
                                        quiet=quiet)
            # Target link-layer address
            body += self.make_option(option_type=2, 
                                     option_value=self.eth.convert_mac(ethernet_src_mac),
                                     exit_on_failure=exit_on_failure,
                                     exit_code=exit_code,
                                     quiet=quiet)  
    
            if ethernet_dst_mac is None:
                ethernet_dst_mac = '33:33:00:00:00:01'
    
            if ipv6_dst is None:
                ipv6_dst = 'ff02::1'
    
            return self.make_packet(ethernet_src_mac=ethernet_src_mac, 
                                    ethernet_dst_mac=ethernet_dst_mac, 
                                    ipv6_src=ipv6_src, 
                                    ipv6_dst=ipv6_dst, 
                                    ipv6_flow=0, 
                                    icmpv6_type=self.types['Neighbor Advertisement'], 
                                    icmpv6_code=0, 
                                    icmpv6_body=body,
                                    exit_on_failure=exit_on_failure, 
                                    exit_code=exit_code, 
                                    quiet=quiet)

        except TypeError:
            error_text = 'Failed to make IPCMv6 Neighbor Advertisement packet!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_echo_request_packet(self, 
                                 ethernet_src_mac: str = '01:23:45:67:89:0a', 
                                 ethernet_dst_mac: str = '01:23:45:67:89:0b', 
                                 ipv6_src: str = 'fd00::1', 
                                 ipv6_dst: str = 'fd00::2', 
                                 id: int = 1, 
                                 sequence: int = 1,
                                 exit_on_failure: bool = True,
                                 exit_code: int = 51,
                                 quiet: bool = False) -> Union[None, bytes]:
        """
        Make ICMPv6 Echo (ping) request packet
        :param ethernet_src_mac: 
        :param ethernet_dst_mac: 
        :param ipv6_src: 
        :param ipv6_dst: 
        :param id: 
        :param sequence: 
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 51)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: 
        """
        try:
            body = pack('!2H', id, sequence)
            for index in range(0, 56, 1):
                body += pack('B', index)
            return self.make_packet(ethernet_src_mac=ethernet_src_mac, 
                                    ethernet_dst_mac=ethernet_dst_mac, 
                                    ipv6_src=ipv6_src, 
                                    ipv6_dst=ipv6_dst, 
                                    ipv6_flow=0, 
                                    icmpv6_type=self.types['Echo (ping) request'], 
                                    icmpv6_code=0, 
                                    icmpv6_body=body,
                                    exit_on_failure=exit_on_failure,
                                    exit_code=exit_code,
                                    quiet=quiet)

        except TypeError:
            error_text = 'Failed to make ICMPv6 Echo (ping) request packet!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_echo_reply_packet(self, 
                               ethernet_src_mac: str = '01:23:45:67:89:0a', 
                               ethernet_dst_mac: str = '01:23:45:67:89:0b', 
                               ipv6_src: str = 'fd00::1', 
                               ipv6_dst: str = 'fd00::2', 
                               id: int = 1, 
                               sequence: int = 1, 
                               data: Union[None, bytes] = None,
                               exit_on_failure: bool = True,
                               exit_code: int = 52,
                               quiet: bool = False) -> Union[None, bytes]:
        """
        Make ICMPv6 Echo (ping) reply packet
        :param ethernet_src_mac: 
        :param ethernet_dst_mac: 
        :param ipv6_src: 
        :param ipv6_dst: 
        :param id: 
        :param sequence: 
        :param data: 
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 52)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: 
        """
        try:
            body = pack('!2H', id, sequence)
            if data is None:
                for index in range(0, 56, 1):
                    body += pack('B', index)
            else:
                body += data
            return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                    ethernet_dst_mac=ethernet_dst_mac,
                                    ipv6_src=ipv6_src,
                                    ipv6_dst=ipv6_dst,
                                    ipv6_flow=0,
                                    icmpv6_type=self.types['Echo (ping) reply'],
                                    icmpv6_code=0,
                                    icmpv6_body=body,
                                    exit_on_failure=exit_on_failure,
                                    exit_code=exit_code,
                                    quiet=quiet)

        except TypeError:
            error_text = 'Failed to make ICMPv6 Echo (ping) reply packet!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

    def make_multicast_listener_report_packet(self, 
                                              ethernet_src_mac: str = '01:23:45:67:89:0a',
                                              ethernet_dst_mac: Union[None, str] = None,
                                              ipv6_src: str = 'fd00::1',
                                              ipv6_dst: Union[None, str] = None,
                                              multicast_addresses: List[str] = ['ff02::1', 'ff02::16'],
                                              exit_on_failure: bool = True,
                                              exit_code: int = 53,
                                              quiet: bool = False) -> Union[None, bytes]:
        """
        Make ICMPv6 Multicast listener report packet
        :param ethernet_src_mac: 
        :param ethernet_dst_mac: 
        :param ipv6_src: 
        :param ipv6_dst: 
        :param multicast_addresses: 
        :param exit_on_failure: Exit in case of error (default: False)
        :param exit_code: Set exit code integer (default: 53)
        :param quiet: Quiet mode, if True no console output (default: False)
        :return: 
        """
        try:
            if ethernet_dst_mac is None:
                ethernet_dst_mac = '33:33:00:00:00:16'
            
            if ipv6_dst is None:
                ipv6_dst = 'ff02::16'
            
            body = pack('!2H', 0, len(multicast_addresses))
            
            for multicast_address in multicast_addresses:
                body += pack('!' '2B' 'H', 4, 0, 0)
                body += self.ipv6.pack_addr(ipv6_address=multicast_address,
                                            exit_on_failure=exit_on_failure,
                                            exit_code=exit_code,
                                            quiet=quiet)

            return self.make_packet(ethernet_src_mac=ethernet_src_mac,
                                    ethernet_dst_mac=ethernet_dst_mac,
                                    ipv6_src=ipv6_src,
                                    ipv6_dst=ipv6_dst,
                                    ipv6_flow=0,
                                    icmpv6_type=self.types['Multicast listener report'],
                                    icmpv6_code=0,
                                    icmpv6_body=body,
                                    exit_on_failure=exit_on_failure,
                                    exit_code=exit_code,
                                    quiet=quiet)

        except TypeError:
            error_text = 'Failed to make ICMPv6 Multicast listener report packet!'

        if not quiet:
            self.base.print_error(error_text)
        if exit_on_failure:
            exit(exit_code)
        else:
            return None

# endregion


# # region Raw MDNS
# class MDNS_raw:
#
#     Base = None
#     eth = None
#     ip = None
#     ipv6 = None
#     udp = None
#     dns = None
#
#     def __init__(self):
#         self.Base = Base()
#         self.eth = Ethernet_raw()
#         self.ip = IP_raw()
#         self.ipv6 = IPv6_raw()
#         self.udp = UDP_raw()
#         self.dns = DNS_raw()
#
#     def make_response_packet(self, src_mac, dst_mac, src_ip, dst_ip, queries=[], answers_address=[], name_servers={},
#                              src_port=5353, dst_port=5353, tid=0, flags=0x8400):
#         transaction_id = tid
#         dns_flags = flags
#         questions = len(queries)
#         answer_rrs = len(answers_address)
#         authority_rrs = len(name_servers.keys())
#         additional_rrs = len(name_servers.keys())
#
#         dns_packet = pack('!6H', transaction_id, dns_flags, questions, answer_rrs, authority_rrs, additional_rrs)
#
#         for query in queries:
#             query_name = query['name']
#             query_type = query['type']
#             query_class = query['class']
#
#             if query_name.endswith('.'):
#                 query_name = query_name[:-1]
#
#             dns_packet += self.dns.pack_dns_name(query_name)
#             dns_packet += pack('!2H', query_type, query_class)
#
#         for address in answers_address:
#             if 'name' in address.keys():
#                 dns_packet += self.dns.pack_dns_name(address['name'])
#             else:
#                 dns_packet += pack('!H', 0xc00c)
#
#             if address['type'] == 1:
#                 dns_packet += pack('!' '2H' 'I' 'H' '4s', address['type'], address['class'], address['ttl'],
#                                    4, inet_aton(address['address']))
#
#             elif address['type'] == 28:
#                 dns_packet += pack('!' '2H' 'I' 'H' '16s', address['type'], address['class'], address['ttl'],
#                                    16, inet_pton(AF_INET6, address['address']))
#
#             elif address['type'] == 12:
#                 domain = self.dns.pack_dns_name(address['address'])
#                 dns_packet += pack('!' '2H' 'I' 'H', address['type'], address['class'], address['ttl'],
#                                    len(domain))
#                 dns_packet += domain
#
#             else:
#                 return None
#
#         if self.Base.ip_address_validation(src_ip):
#             eth_header = self.eth.make_header(src_mac, dst_mac, self.ip.header_type)
#             network_header = self.ip.make_header(src_ip, dst_ip, len(dns_packet),
#                                                  self.udp.header_length, self.udp.header_type)
#             transport_header = self.udp.make_header(src_port, dst_port, len(dns_packet))
#
#         elif self.Base.ipv6_address_validation(src_ip):
#             eth_header = self.eth.make_header(src_mac, dst_mac, self.ipv6.header_type)
#             network_header = self.ipv6.make_header(src_ip, dst_ip, 0, len(dns_packet) + self.udp.header_length,
#                                                    self.udp.header_type)
#             transport_header = self.udp.make_header_with_ipv6_checksum(src_ip, dst_ip, src_port, dst_port,
#                                                                        len(dns_packet), dns_packet)
#
#         else:
#             return None
#
#         return eth_header + network_header + transport_header + dns_packet
#
#     def make_request_packet(self, src_mac, src_ip, queries=[], dst_ip='224.0.0.251', dst_mac='01:00:5e:00:00:fb',
#                             tid=0, flags=0, src_port=5353, dst_port=5353):
#         transaction_id = tid
#         dns_flags = flags
#         questions = len(queries)
#         answer_rrs = 0
#         authority_rrs = 0
#         additional_rrs = 0
#
#         dns_packet = pack('!6H', transaction_id, dns_flags, questions, answer_rrs, authority_rrs, additional_rrs)
#         for query in queries:
#             dns_packet += self.dns.pack_dns_name(query['name'])
#             dns_packet += pack('!2H', query['type'], query['class'])
#
#         eth_header = self.eth.make_header(src_mac, dst_mac, self.ip.header_type)
#         ip_header = self.ip.make_header(src_ip, dst_ip, len(dns_packet), 8, self.udp.header_type)
#         udp_header = self.udp.make_header(src_port, dst_port, len(dns_packet))
#
#         return eth_header + ip_header + udp_header + dns_packet
#
#     def make_ipv6_request_packet(self, src_mac, src_ip, queries=[], dst_ip='ff02::fb', dst_mac='33:33:00:00:00:fb',
#                                  tid=0, flags=0, src_port=5353, dst_port=5353):
#         transaction_id = tid
#         dns_flags = flags
#         questions = len(queries)
#         answer_rrs = 0
#         authority_rrs = 0
#         additional_rrs = 0
#
#         dns_packet = pack('!6H', transaction_id, dns_flags, questions, answer_rrs, authority_rrs, additional_rrs)
#         for query in queries:
#             dns_packet += self.dns.pack_dns_name(query['name'])
#             dns_packet += pack('!2H', query['type'], query['class'])
#
#         eth_header = self.eth.make_header(src_mac, dst_mac, self.ipv6.header_type)
#         ipv6_header = self.ipv6.make_header(src_ip, dst_ip, 0, len(dns_packet) + self.udp.header_length,
#                                             self.udp.header_type)
#         udp_header = self.udp.make_header_with_ipv6_checksum(src_ip, dst_ip, src_port, dst_port,
#                                                              len(dns_packet), dns_packet)
#
#         return eth_header + ipv6_header + udp_header + dns_packet
#
#     @staticmethod
#     def parse_packet(packet):
#         mdns_minimal_packet_length = 12
#
#         if len(packet) < mdns_minimal_packet_length:
#             return None
#
#         mdns_detailed = unpack('!6H', packet[:mdns_minimal_packet_length])
#
#         mdns_packet = {
#             'transaction-id': int(mdns_detailed[0]),
#             'flags':          int(mdns_detailed[1]),
#             'questions':      int(mdns_detailed[2]),
#             'answer-rrs':     int(mdns_detailed[3]),
#             'authority-rrs':  int(mdns_detailed[4]),
#             'additional-rrs': int(mdns_detailed[5]),
#         }
#
#         queries = []
#         answers = []
#         authority = []
#         additional = []
#
#         if len(packet) > mdns_minimal_packet_length:
#
#             number_of_question = 0
#             number_of_answers = 0
#             position = mdns_minimal_packet_length
#
#             while number_of_question < mdns_packet['questions']:
#
#                 query_name = ''
#                 query_name_length = int(unpack('B', packet[position:position + 1])[0])
#
#                 while query_name_length != 0:
#                     query_name += ''.join([str(x) for x in packet[position + 1:position + query_name_length + 1]]) + '.'
#                     position += query_name_length + 1
#                     query_name_length = int(unpack('B', packet[position:position + 1])[0])
#
#                 query_type = int(unpack('!H', packet[position + 1:position + 3])[0])
#                 query_class = int(unpack('!H', packet[position + 3:position + 5])[0])
#                 position += 5
#
#                 queries.append({
#                     'name':  query_name,
#                     'type':  query_type,
#                     'class': query_class
#                 })
#
#                 number_of_question += 1
#
#             while number_of_answers < mdns_packet['answer-rrs']:
#
#                 name = ''
#                 name_length = int(unpack('B', packet[position:position + 1])[0])
#
#                 while name_length != 0:
#                     name += ''.join([str(x) for x in packet[position + 1:position + name_length + 1]]) + '.'
#                     position += name_length + 1
#                     name_length = int(unpack('B', packet[position:position + 1])[0])
#
#                 type = int(unpack('!H', packet[position + 1:position + 3])[0])
#                 answer_class = int(unpack('!H', packet[position + 3:position + 5])[0])
#                 ttl = int(unpack('!I', packet[position + 5:position + 9])[0])
#                 data_len = int(unpack('!H', packet[position + 9:position + 11])[0])
#                 position += 11
#
#                 if type == 1:
#                     data = inet_ntoa(unpack('!4s', packet[position:position + 4])[0])
#                     position += data_len
#
#                 elif type == 28:
#                     data = inet_ntop(AF_INET6, unpack('!16s', packet[position:position + 16])[0])
#                     position += data_len
#
#                 else:
#                     data = ''
#                     for _ in range(data_len):
#                         data += str(unpack('c', packet[position:position + 1])[0]).decode(errors='replace')
#                         position += 1
#
#                 answers.append({
#                     'name': name,
#                     'type': type,
#                     'class': answer_class,
#                     'ttl': ttl,
#                     'data length': data_len,
#                     'data': data
#                 })
#
#                 number_of_answers += 1
#
#         mdns_packet['queries'] = queries
#         mdns_packet['answers'] = answers
#
#         return mdns_packet
#
#     def make_a_query(self, src_mac, src_ip, names=[], dst_ip='224.0.0.251', dst_mac='01:00:5e:00:00:fb',
#                      tid=0, flags=0, src_port=5353, dst_port=5353):
#         queries = []
#
#         for name in names:
#             queries.append({'type': 1, 'class': 1, 'name': name})
#
#         return self.make_request_packet(src_mac=src_mac, dst_mac=dst_mac,
#                                         src_ip=src_ip, dst_ip=dst_ip,
#                                         src_port=src_port, dst_port=dst_port,
#                                         tid=tid,
#                                         flags=flags,
#                                         queries=queries)
#
#     def make_ipv6_a_query(self, src_mac, src_ip, names=[], dst_ip='ff02::fb', dst_mac='33:33:00:00:00:fb',
#                           tid=0, flags=0, src_port=5353, dst_port=5353):
#         queries = []
#
#         for name in names:
#             queries.append({'type': 1, 'class': 1, 'name': name})
#
#         return self.make_ipv6_request_packet(src_mac=src_mac, dst_mac=dst_mac,
#                                              src_ip=src_ip, dst_ip=dst_ip,
#                                              src_port=src_port, dst_port=dst_port,
#                                              tid=tid,
#                                              flags=flags,
#                                              queries=queries)
#
#     def make_aaaa_query(self, src_mac, src_ip, names=[], dst_ip='224.0.0.251', dst_mac='01:00:5e:00:00:fb',
#                         tid=0, flags=0, src_port=5353, dst_port=5353):
#         queries = []
#
#         for name in names:
#             queries.append({'type': 28, 'class': 1, 'name': name})
#
#         return self.make_request_packet(src_mac=src_mac, dst_mac=dst_mac,
#                                         src_ip=src_ip, dst_ip=dst_ip,
#                                         src_port=src_port, dst_port=dst_port,
#                                         tid=tid,
#                                         flags=flags,
#                                         queries=queries)
#
#     def make_ipv6_aaaa_query(self, src_mac, src_ip, names=[], dst_ip='ff02::fb', dst_mac='33:33:00:00:00:fb',
#                              tid=0, flags=0, src_port=5353, dst_port=5353):
#         queries = []
#
#         for name in names:
#             queries.append({'type': 28, 'class': 1, 'name': name})
#
#         return self.make_ipv6_request_packet(src_mac=src_mac, dst_mac=dst_mac,
#                                              src_ip=src_ip, dst_ip=dst_ip,
#                                              src_port=src_port, dst_port=dst_port,
#                                              tid=tid,
#                                              flags=flags,
#                                              queries=queries)
#
#     def make_any_query(self, src_mac, src_ip, names=[], dst_ip='224.0.0.251', dst_mac='01:00:5e:00:00:fb',
#                        tid=0, flags=0, src_port=5353, dst_port=5353):
#         queries = []
#
#         for name in names:
#             queries.append({'type': 255, 'class': 1, 'name': name})
#
#         return self.make_request_packet(src_mac=src_mac, dst_mac=dst_mac,
#                                         src_ip=src_ip, dst_ip=dst_ip,
#                                         src_port=src_port, dst_port=dst_port,
#                                         tid=tid,
#                                         flags=flags,
#                                         queries=queries)
#
#     def make_ipv6_any_query(self, src_mac, src_ip, names=[], dst_ip='ff02::fb', dst_mac='33:33:00:00:00:fb',
#                             tid=0, flags=0, src_port=5353, dst_port=5353):
#         queries = []
#
#         for name in names:
#             queries.append({'type': 255, 'class': 1, 'name': name})
#
#         return self.make_ipv6_request_packet(src_mac=src_mac, dst_mac=dst_mac,
#                                              src_ip=src_ip, dst_ip=dst_ip,
#                                              src_port=src_port, dst_port=dst_port,
#                                              tid=tid,
#                                              flags=flags,
#                                              queries=queries)
#
# # endregion


# region Raw Sniffer
class RawSniff:

    # region variables
    raw_socket = None
    # endregion

    # region Init
    def __init__(self):
        self.Base: Base = Base()
        self.eth: RawEthernet = RawEthernet()
        self.arp: RawARP = RawARP()
        self.ipv4: RawIPv4 = RawIPv4()
        self.ipv6: RawIPv6 = RawIPv6()
        self.udp: RawUDP = RawUDP()
        self.dns: RawDNS = RawDNS()
        self.dhcpv4: RawDHCPv4 = RawDHCPv4()
        self.icmpv4: RawICMPv4 = RawICMPv4()
        self.dhcpv6: RawDHCPv6 = RawDHCPv6()
        self.icmpv6: RawICMPv6 = RawICMPv6()
    # endregion

    # region Start sniffer
    def start(self, protocols, prn, filters={}):

        # region Create RAW socket for sniffing
        self.raw_socket = socket(AF_PACKET, SOCK_RAW, htons(0x0003))
        # endregion

        # region Start sniffing
        while True:

            # region Sniff packets from RAW socket
            packets: Tuple[bytes, Any] = self.raw_socket.recvfrom(65535)
            for packet in packets:

                # region Try
                try:

                    # region Parse Ethernet header
                    ethernet_header: Union[bytes, Any] = packet[0:self.eth.header_length]
                    ethernet_header_dict: Union[None, Dict[str, Union[int, str]]] = \
                        self.eth.parse_header(packet=ethernet_header, exit_on_failure=False, quiet=True)
                    # endregion

                    # region Could not parse Ethernet header - break
                    assert ethernet_header_dict is not None, 'Bad Ethernet packet!'
                    # endregion

                    # region Ethernet filter
                    if 'Ethernet' in filters.keys():

                        if 'source' in filters['Ethernet'].keys():
                            assert ethernet_header_dict['source'] == filters['Ethernet']['source'], \
                                'Bad Ethernet source MAC address!'

                        if 'destination' in filters['Ethernet'].keys():
                            assert ethernet_header_dict['destination'] == filters['Ethernet']['destination'], \
                                'Bad Ethernet destination MAC address!'

                        if 'not-source' in filters['Ethernet'].keys():
                            assert ethernet_header_dict['source'] != filters['Ethernet']['not-source'], \
                                'Bad Ethernet source MAC address!'

                        if 'not-destination' in filters['Ethernet'].keys():
                            assert ethernet_header_dict['destination'] != filters['Ethernet']['not-destination'], \
                                'Bad Ethernet destination MAC address!'
                    # endregion

                    # region ARP packet

                    # 2054 - Type of ARP packet (0x0806)
                    if 'ARP' in protocols and ethernet_header_dict['type'] == self.arp.packet_type:

                        # region Parse ARP packet
                        arp_header: Union[bytes, Any] = \
                            packet[self.eth.header_length:self.eth.header_length + self.arp.packet_length]
                        arp_packet_dict: Union[None, Dict[str, Union[int, str]]] = \
                            self.arp.parse_packet(packet=arp_header, exit_on_failure=False, quiet=True)
                        # endregion

                        # region Could not parse ARP packet - break
                        assert arp_packet_dict is not None, 'Bad ARP packet!'
                        # endregion

                        # region ARP filter
                        if 'ARP' in filters.keys():
                            if 'opcode' in filters['ARP'].keys():
                                assert arp_packet_dict['opcode'] == filters['ARP']['opcode'], \
                                    'Bad ARP opcode!'
                        # endregion

                        # region Call function with full ARP packet
                        prn({
                            'Ethernet': ethernet_header_dict,
                            'ARP': arp_packet_dict
                        })
                        # endregion

                    # endregion

                    # region IPv4 packet

                    # 2048 - Type of IPv4 packet (0x0800)
                    if 'IPv4' in protocols and ethernet_header_dict['type'] == self.ipv4.header_type:

                        # region Parse IPv4 header
                        ipv4_header: Union[bytes, Any] = packet[self.eth.header_length:]
                        ipv4_header_dict: Union[None, Dict[str, Union[int, str]]] = \
                            self.ipv4.parse_header(packet=ipv4_header, exit_on_failure=False, quiet=True)
                        # endregion

                        # region Could not parse IPv4 header - break
                        assert ipv4_header_dict is not None, 'Bad IPv4 packet!'
                        # endregion

                        # region IPv4 filter
                        if 'IPv4' in filters.keys():

                            if 'source-ip' in filters['IPv4'].keys():
                                assert ipv4_header_dict['source-ip'] == filters['IPv4']['source-ip'], \
                                    'Bad source IPv4 address'

                            if 'destination-ip' in filters['IPv4'].keys():
                                assert ipv4_header_dict['destination-ip'] == filters['IPv4']['destination-ip'], \
                                    'Bad destination IPv4 address'

                            if 'not-source-ip' in filters['IPv4'].keys():
                                assert ipv4_header_dict['source-ip'] != filters['IPv4']['not-source-ip'], \
                                    'Bad source IPv4 address'

                            if 'not-destination-ip' in filters['IPv4'].keys():
                                assert ipv4_header_dict['destination-ip'] != filters['IPv4']['not-destination-ip'], \
                                    'Bad destination IPv4 address'
                        # endregion

                        # region UDP
                        if 'UDP' in protocols and ipv4_header_dict['protocol'] == self.udp.header_type:

                            # region Parse UDP header
                            udp_header_offset: int = self.eth.header_length + (ipv4_header_dict['length'] * 4)
                            udp_header: Union[bytes, Any] = \
                                packet[udp_header_offset:udp_header_offset + self.udp.header_length]
                            udp_header_dict: Union[None, Dict[str, Union[int, str]]] = \
                                self.udp.parse_header(packet=udp_header, exit_on_failure=False, quiet=True)
                            # endregion

                            # region Could not parse UDP header - break
                            assert udp_header_dict is not None, 'Bad UDP packet!'
                            # endregion

                            # region UDP filter
                            if 'UDP' in filters.keys():

                                if 'source-port' in filters['UDP'].keys():
                                    assert udp_header_dict['source-port'] == filters['UDP']['source-port'], \
                                        'Bad UDP source port!'

                                if 'not-source-port' in filters['UDP'].keys():
                                    assert udp_header_dict['source-port'] != filters['UDP']['source-port'], \
                                        'Bad UDP source port!'

                                if 'destination-port' in filters['UDP'].keys():
                                    assert udp_header_dict['destination-port'] == filters['UDP']['destination-port'], \
                                        'Bad UDP destination port!'

                                if 'not-destination-port' in filters['UDP'].keys():
                                    assert udp_header_dict['destination-port'] != filters['UDP']['destination-port'], \
                                        'Bad UDP destination port!'
                            # endregion

                            # region DHCPv4 packet
                            if 'DHCPv4' in protocols:

                                # region Parse DHCPv4 packet
                                dhcpv4_packet_offset: int = udp_header_offset + self.udp.header_length
                                dhcpv4_packet: Union[bytes, Any] = packet[dhcpv4_packet_offset:]
                                dhcpv4_packet_dict = self.dhcpv4.parse_packet(dhcpv4_packet)
                                # endregion

                                # region Could not parse DHCPv4 packet - break
                                assert dhcpv4_packet_dict is not None, 'Bad DHCPv4 packet!'
                                # endregion

                                # region Call function with full DHCPv4 packet
                                full_dhcpv4_packet = {
                                    'Ethernet': ethernet_header_dict,
                                    'IPv4': ipv4_header_dict,
                                    'UDP': udp_header_dict
                                }
                                full_dhcpv4_packet.update(dhcpv4_packet_dict)

                                prn(full_dhcpv4_packet)
                                # endregion

                            # endregion

                            # region DNS packet
                            if 'DNS' in protocols:

                                # region Parse DNS packet
                                dns_packet_offset: int = udp_header_offset + self.udp.header_length
                                dns_packet: Union[bytes, Any] = packet[dns_packet_offset:]
                                dns_packet_dict: Union[None, Dict[str, Union[int, str, Dict[str, Union[int, str]]]]] = \
                                    self.dns.parse_packet(packet=dns_packet, exit_on_failure=False, quiet=True)
                                # endregion

                                # region Could not parse DNS packet - break
                                assert dns_packet_dict is not None, 'Bad DNS packet!'
                                # endregion

                                # region Call function with full DNS packet
                                prn({
                                    'Ethernet': ethernet_header_dict,
                                    'IPv4': ipv4_header_dict,
                                    'UDP': udp_header_dict,
                                    'DNS': dns_packet_dict
                                })
                                # endregion

                            # endregion

                            # # region MDNS packet
                            #
                            # if 'MDNS' in protocols and udp_header_dict['destination-port'] == 5353:
                            #
                            #     # region Parse DNS request packet
                            #     mdns_packet_offset = udp_header_offset + self.udp.header_length
                            #     mdns_packet = packet[mdns_packet_offset:]
                            #     mdns_packet_dict = self.mdns.parse_packet(mdns_packet)
                            #     # endregion
                            #
                            #     # region Could not parse DNS request packet - break
                            #     if mdns_packet_dict is None:
                            #         break
                            #     # endregion
                            #
                            #     # region Call function with full DNS packet
                            #     prn({
                            #         'Ethernet': ethernet_header_dict,
                            #         'IP': ip_header_dict,
                            #         'UDP': udp_header_dict,
                            #         'MDNS': mdns_packet_dict
                            #     })
                            #     # endregion
                            #
                            # # endregion

                        # endregion

                        # region ICMPv4
                        if 'ICMPv4' in protocols and ipv4_header_dict['protocol'] == self.icmpv4.packet_type:

                            # region Parse ICMPv4 packet
                            icmpv4_packet_offset: int = self.eth.header_length + (ipv4_header_dict['length'] * 4)
                            icmpv4_packet: Union[bytes, Any] = \
                                packet[icmpv4_packet_offset:]
                            icmpv4_packet_dict: Union[None, Dict[str, Union[int, str, bytes]]] = \
                                self.icmpv4.parse_packet(packet=icmpv4_packet, exit_on_failure=False, quiet=True)
                            # endregion

                            # region Could not parse ICMPv4 packet - break
                            assert icmpv4_packet_dict is not None, 'Bad ICMPv4 packet!'
                            # endregion

                            # region Call function with full ICMPv4 packet
                            prn({
                                'Ethernet': ethernet_header_dict,
                                'IPv4': ipv4_header_dict,
                                'ICMPv4': icmpv4_packet_dict
                            })
                            # endregion

                        # endregion

                    # endregion

                    # region IPv6 packet

                    # 34525 - Type of IP packet (0x86dd)
                    if 'IPv6' in protocols and ethernet_header_dict['type'] == self.ipv6.header_type:

                        # region Parse IPv6 header
                        ipv6_header: Union[bytes, Any] = \
                            packet[self.eth.header_length:self.eth.header_length + self.ipv6.header_length]
                        ipv6_header_dict: Union[None, Dict[str, Union[int, str]]] = \
                            self.ipv6.parse_header(packet=ipv6_header, exit_on_failure=False, quiet=True)
                        # endregion

                        # region Could not parse IPv6 header - break
                        assert ipv6_header_dict is not None, 'Bad IPv6 packet!'
                        # endregion

                        # region IPv6 filter
                        if 'IPv6' in filters.keys():

                            if 'source-ip' in filters['IPv6'].keys():
                                assert ipv6_header_dict['source-ip'] == filters['IPv6']['source-ip'], \
                                    'Bad source IPv6 address!'

                            if 'destination-ip' in filters['IPv6'].keys():
                                assert ipv6_header_dict['destination-ip'] == filters['IPv6']['destination-ip'], \
                                    'Bad destination IPv6 address!'

                            if 'not-source-ip' in filters['IPv6'].keys():
                                assert ipv6_header_dict['source-ip'] != filters['IPv6']['not-source-ip'], \
                                    'Bad source IPv6 address!'

                            if 'not-destination-ip' in filters['IPv6'].keys():
                                assert ipv6_header_dict['destination-ip'] != filters['IPv6']['not-destination-ip'], \
                                    'Bad destination IPv6 address!'

                        # endregion

                        # region UDP
                        if 'UDP' in protocols and ipv6_header_dict['next-header'] == self.udp.header_type:

                            # region Parse UDP header
                            udp_header_offset: int = self.eth.header_length + self.ipv6.header_length
                            udp_header: Union[bytes, Any] = \
                                packet[udp_header_offset:udp_header_offset + self.udp.header_length]
                            udp_header_dict: Union[None, Dict[str, Union[int, str]]] = \
                                self.udp.parse_header(packet=udp_header, exit_on_failure=False, quiet=True)
                            # endregion

                            # region Could not parse UDP header - break
                            assert udp_header is not None, 'Bad UDP packet!'
                            # endregion

                            # region UDP filter
                            if 'UDP' in filters.keys():

                                if 'source-port' in filters['UDP'].keys():
                                    assert udp_header_dict['source-port'] != filters['UDP']['source-port'], \
                                        'Bad UDP source port!'

                                if 'destination-port' in filters['UDP'].keys():
                                    assert udp_header_dict['destination-port'] == filters['UDP']['destination-port'], \
                                        'Bad UDP destination port!'
                            # endregion

                            # region DNS packet
                            if 'DNS' in protocols:

                                # region Parse DNS request packet
                                dns_packet_offset: int = udp_header_offset + self.udp.header_length
                                dns_packet: Union[bytes, Any] = packet[dns_packet_offset:]
                                dns_packet_dict: Union[None, Dict[str, Union[int, str, Dict[str, Union[int, str]]]]] = \
                                    self.dns.parse_packet(packet=dns_packet, exit_on_failure=False, quiet=True)
                                # endregion

                                # region Could not parse DNS request packet - break
                                assert dns_packet_dict is not None, 'Bad DNS packet!'
                                # endregion

                                # region Call function with full DNS packet
                                prn({
                                    'Ethernet': ethernet_header_dict,
                                    'IPv6': ipv6_header_dict,
                                    'UDP': udp_header_dict,
                                    'DNS': dns_packet_dict
                                })
                                # endregion

                            # endregion

                            # # region MDNS packet
                            #
                            # if 'MDNS' in protocols and udp_header_dict['destination-port'] == 5353:
                            #
                            #     # region Parse DNS request packet
                            #     mdns_packet_offset = udp_header_offset + self.udp.header_length
                            #     mdns_packet = packet[mdns_packet_offset:]
                            #     mdns_packet_dict = self.mdns.parse_packet(mdns_packet)
                            #     # endregion
                            #
                            #     # region Could not parse DNS request packet - break
                            #     if mdns_packet_dict is None:
                            #         break
                            #     # endregion
                            #
                            #     # region Call function with full DNS packet
                            #     prn({
                            #         'Ethernet': ethernet_header_dict,
                            #         'IPv6': ipv6_header_dict,
                            #         'UDP': udp_header_dict,
                            #         'MDNS': mdns_packet_dict
                            #     })
                            #     # endregion
                            #
                            # # endregion

                            # region DHCPv6 packet
                            if 'DHCPv6' in protocols:

                                # region Parse DHCPv6 request packet
                                dhcpv6_packet_offset = udp_header_offset + self.udp.header_length
                                dhcpv6_packet = packet[dhcpv6_packet_offset:]
                                dhcpv6_packet_dict = self.dhcpv6.parse_packet(dhcpv6_packet)
                                # endregion

                                # region Could not parse DHCPv6 request packet - break
                                if dhcpv6_packet_dict is None:
                                    break
                                # endregion

                                # region Call function with full DHCPv6 packet
                                prn({
                                    'Ethernet': ethernet_header_dict,
                                    'IPv6': ipv6_header_dict,
                                    'UDP': udp_header_dict,
                                    'DHCPv6': dhcpv6_packet_dict
                                })
                                # endregion

                            # endregion

                        # endregion

                        # region ICMPv6
                        if 'ICMPv6' in protocols and ipv6_header_dict['next-header'] == self.icmpv6.packet_type:

                            # region Parse ICMPv6 packet
                            icmpv6_packet_offset = self.eth.header_length + self.ipv6.header_length
                            icmpv6_packet = packet[icmpv6_packet_offset:]
                            icmpv6_packet_dict = self.icmpv6.parse_packet(icmpv6_packet)
                            # endregion

                            # region Could not parse ICMPv6 packet - break
                            if icmpv6_packet_dict is None:
                                break
                            # endregion

                            # region Call function with full ICMPv6 packet
                            prn({
                                'Ethernet': ethernet_header_dict,
                                'IPv6': ipv6_header_dict,
                                'ICMPv6': icmpv6_packet_dict
                            })
                            # endregion

                        # endregion

                    # endregion

                # endregion

                # region Exception - KeyboardInterrupt
                except KeyboardInterrupt:
                    self.Base.print_info('Exit')
                    exit(0)
                # endregion

                # region Exception - AssertionError
                except AssertionError:
                    pass
                # endregion

            # endregion

        # endregion

    # endregion

# endregion
