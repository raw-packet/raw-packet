# region Description
"""
network.py: Unit tests for Raw-packet network classes
Author: Vladimir Ivanov
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import

# region Add project root path
from sys import path
from os.path import dirname, abspath
path.append(dirname(dirname(abspath(__file__))))
# endregion

# region Raw-packet modules
from raw_packet.Utils.base import Base
from raw_packet.Utils.network import RawEthernet, RawARP, RawIPv4, RawIPv6, RawUDP
# endregion

# region Import libraries
import unittest
# endregion

# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Main class - NetworkTest
class NetworkTest(unittest.TestCase):

    # region Properties
    base: Base = Base()
    ethernet: RawEthernet = RawEthernet()
    arp: RawARP = RawARP()
    ipv4: RawIPv4 = RawIPv4()
    ipv6: RawIPv6 = RawIPv6()
    udp: RawUDP = RawUDP()
    # endregion

    # region Test RawEthernet methods
    def test_ethernet_init(self):
        self.assertIn('00:18:de', self.ethernet.macs)

    def test_ethernet_make_random_mac(self):
        self.assertTrue(self.base.mac_address_validation(self.ethernet.make_random_mac()))

    def test_ethernet_convert_mac(self):
        # Convert string MAC address to bytes
        self.assertEqual(self.ethernet.convert_mac('30:31:32:33:34:35', True, 41), b'012345')
        # Convert bytes MAC address to string
        self.assertEqual(self.ethernet.convert_mac(b'012345', True, 41), '30:31:32:33:34:35')
        # Bad MAC address string
        self.assertIsNone(self.ethernet.convert_mac('30:31:32:33:34:356', False, 41))
        # Bad MAC address string
        self.assertIsNone(self.ethernet.convert_mac('30:31:32:33:34567', False, 41))
        # Bad MAC address bytes
        self.assertIsNone(self.ethernet.convert_mac(b'01234', False, 41))

    def test_ethernet_get_mac_prefix(self):
        # Prefix from MAC address string
        self.assertEqual(self.ethernet.get_mac_prefix('ab:cd:ef:01:23:45', 3, True, 42), 'ABCDEF')
        # Prefix from MAC address bytes
        self.assertEqual(self.ethernet.get_mac_prefix(b'012345', 3, True, 42), '303132')
        # Bad MAC address string
        self.assertIsNone(self.ethernet.get_mac_prefix('30:31:32:33:34:356', 3, False, 42))
        # Bad MAC address string
        self.assertIsNone(self.ethernet.get_mac_prefix('30:31:32:33:34567', 3, False, 42))
        # Bad MAC address bytes
        self.assertIsNone(self.ethernet.get_mac_prefix(b'01234', 3, False, 42))

    def test_ethernet_parse_header(self):
        # Normal packet
        self.assertEqual(self.ethernet.parse_header(b'6789@A012345\x08\x00', True, 43),
                         {'destination': '36:37:38:39:40:41', 'source': '30:31:32:33:34:35', 'type': 2048})
        # Bad packet
        self.assertIsNone(self.ethernet.parse_header(b'6789@A012345\x08\x00\x01', False, 43))

    def test_ethernet_make_header(self):
        # MAC addresses string
        self.assertEqual(self.ethernet.make_header('30:31:32:33:34:35', '36:37:38:39:40:41', 2048, True, 44),
                         b'6789@A012345\x08\x00')
        # Bad first MAC address bytes
        self.assertIsNone(self.ethernet.make_header('30:31:32:33:34567', '36:37:38:39:40:41', 2048, False, 44))
        # Bad second MAC address bytes
        self.assertIsNone(self.ethernet.make_header('30:31:32:33:34:56', '36:37:38:39:40123', 2048, False, 44))
    # endregion

    # region Test RawARP methods
    def test_arp_parse_packet(self):
        # Normal packet
        self.assertEqual(self.arp.parse_packet(b'\x00\x01\x08\x00\x06\x04\x00\x01\x01#Eg\x89\n\xc0\xa8\x01\x01\x01' +
                                               b'#Eg\x89\x0b\xc0\xa8\x01\x02', True, 45),
                         {'hardware-type': 1, 'protocol-type': 2048, 'hardware-size': 6, 'protocol-size': 4,
                          'opcode': 1, 'sender-mac': '01:23:45:67:89:0a', 'sender-ip': '192.168.1.1',
                          'target-mac': '01:23:45:67:89:0b', 'target-ip': '192.168.1.2'})
        # Bad packet
        self.assertIsNone(self.arp.parse_packet(b'\x00\x01\x08\x00\x06\x04\x00\x01\x01#Eg\x89\n\xc0\xa8\x01\x01\x01' +
                                                b'#Eg\x89\x0b\xc0\xa8\x01\x02\x03', False, 45))

    def test_arp_make_packet(self):
        # Normal
        self.assertEqual(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                              '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', 1, 1, 2048, 6, 4,
                                              True, 46),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x01#Eg\x89\n\xc0\xa8' +
                         b'\x01\x01\x01#Eg\x89\x0b\xc0\xa8\x01\x02')
        # Bad ethernet src MAC address
        self.assertIsNone(self.arp.make_packet('01:23:45:67:890ab', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', 1, 1, 2048, 6, 4,
                                               False, 46))
        # Bad ethernet dst MAC address
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:890ab', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', 1, 1, 2048, 6, 4,
                                               False, 46))
        # Bad sender MAC address
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0a', '01:23:45:67:890ab',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', 1, 1, 2048, 6, 4,
                                               False, 46))
        # Bad target MAC address
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0a', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:890ab', '192.168.1.2', 1, 1, 2048, 6, 4,
                                               False, 46))
        # Bad sender IP address
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.300', '01:23:45:67:89:0b', '192.168.1.2', 1, 1, 2048, 6, 4,
                                               False, 46))
        # Bad target IP address
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.400', 1, 1, 2048, 6, 4,
                                               False, 46))
        # Bad ARP opcode
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', 123123, 1, 2048, 6, 4,
                                               False, 46))
        # Bad hardware type
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', 1, 123123, 2048, 6, 4,
                                               False, 46))
        # Bad protocol type
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', 1, 1, 123123, 6, 4,
                                               False, 46))
        # Bad hardware size
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', 1, 1, 2048, 123123, 4,
                                               False, 46))
        # Bad protocol size
        self.assertIsNone(self.arp.make_packet('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', 1, 1, 2048, 6, 123123,
                                               False, 46))

    def test_arp_make_request(self):
        # Normal
        self.assertEqual(self.arp.make_request('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', True, 47),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x01#Eg\x89\n' +
                         b'\xc0\xa8\x01\x01\x01#Eg\x89\x0b\xc0\xa8\x01\x02')

    def test_arp_make_response(self):
        # Normal
        self.assertEqual(self.arp.make_response('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                                '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', True, 48),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\x01#Eg\x89\n' +
                         b'\xc0\xa8\x01\x01\x01#Eg\x89\x0b\xc0\xa8\x01\x02')

    # endregion

    # region Test RawIPv4 methods
    def test_ipv4_make_random_ip(self):
        self.assertTrue(self.base.ip_address_validation(self.ipv4.make_random_ip()))

    def test_ipv4_parse_header(self):
        # Normal
        self.assertEqual(self.ipv4.parse_header(b'E\x00\x00\x1c\x01\x00\x00\x00@\x11\xf6}' +
                                                b'\xc0\xa8\x01\x01\xc0\xa8\x01\x02', True, 49),
                         {'version': 4, 'length': 5, 'dscp_ecn': 0, 'total-length': 28, 'identification': 256,
                          'flags': 0, 'fragment-offset': 0, 'time-to-live': 64, 'protocol': 17, 'checksum': 63101,
                          'source-ip': '192.168.1.1', 'destination-ip': '192.168.1.2'})
        # Bad packet
        self.assertIsNone(self.ipv4.parse_header(b'\x61\x00\x00\x1c\x8d/\x00\x00@\x11jN' +
                                                 b'\xc0\xa8\x01\x01\xc0\xa8\x01\x02', False, 49))
        # Bad packet
        self.assertIsNone(self.ipv4.parse_header(b'\x61\x00\x00\x1c\x8d/\x00\x00@\x11jN' +
                                                 b'\xc0\xa8\x01\x01\xc0\xa8\x01', False, 49))

    def test_ipv4_make_header(self):
        # Normal
        self.assertEqual(self.ipv4.make_header('192.168.1.1', '192.168.1.2', 1, 0, 8, 17, 64, True, 50),
                         b'E\x00\x00\x1c\x01\x00\x00\x00@\x11\xf6}\xc0\xa8\x01\x01\xc0\xa8\x01\x02')
        # Bad source IP
        self.assertIsNone(self.ipv4.make_header('192.168.1.300', '192.168.1.2', 1, 0, 8, 17, 64, False, 50))
        # Bad destination IP
        self.assertIsNone(self.ipv4.make_header('192.168.1.1', '192.168.1.400', 1, 0, 8, 17, 64, False, 50))
        # Bad identification
        self.assertIsNone(self.ipv4.make_header('192.168.1.1', '192.168.1.2', 123123, 0, 8, 17, 64, False, 50))
        # Bad data length
        self.assertIsNone(self.ipv4.make_header('192.168.1.1', '192.168.1.2', 1, 123123, 8, 17, 64, False, 50))
        # Bad transport protocol header length
        self.assertIsNone(self.ipv4.make_header('192.168.1.1', '192.168.1.2', 1, 0, 123123, 17, 64, False, 50))
        # Bad transport protocol type
        self.assertIsNone(self.ipv4.make_header('192.168.1.1', '192.168.1.2', 1, 0, 8, 123123, 64, False, 50))
        # Bad ttl
        self.assertIsNone(self.ipv4.make_header('192.168.1.1', '192.168.1.2', 1, 0, 8, 17, 123123, False, 50))
    # endregion

    # region Test RawIPv6 methods
    def test_ipv6_make_random_ip(self):
        # Normal
        self.assertTrue(self.base.ipv6_address_validation(self.ipv6.make_random_ip(octets=3,
                                                                                   prefix='fd00::',
                                                                                   exit_on_failure=True,
                                                                                   exit_code=51)))
        # Bad prefix
        self.assertIsNone(self.ipv6.make_random_ip(octets=1, prefix='fd00:::', exit_on_failure=False, exit_code=51))
        # Bad octets count
        self.assertIsNone(self.ipv6.make_random_ip(octets=123, prefix='fd00::', exit_on_failure=False, exit_code=51))

    def test_ipv6_pack_addr(self):
        # Normal
        self.assertEqual(self.ipv6.pack_addr(ipv6_address='3132:3334::1', exit_on_failure=True, exit_code=52),
                         b'1234\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
        # Bad IPv6 address
        self.assertIsNone(self.ipv6.pack_addr(ipv6_address='fd00:::1', exit_on_failure=False, exit_code=52))

    def test_ipv6_parse_header(self):
        # Normal
        self.assertEqual(self.ipv6.parse_header(b'`\x00\x00\x00\x00\x08\x11@\xfd\x00\x00\x00\x00\x00\x00\x00' +
                                                b'\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00' +
                                                b'\x00\x00\x00\x00\x00\x00\x00\x00\x02', True, 53),
                         {'version': 6, 'traffic-class': 0, 'flow-label': 0, 'payload-length': 8, 'next-header': 17,
                          'hop-limit': 64, 'source-ip': 'fd00::1', 'destination-ip': 'fd00::2'})
        # Bad packet
        self.assertIsNone(self.ipv6.parse_header(b'`\x00\x00\x00\x00\x08\x11@\xfd\x00\x00\x00\x00\x00\x00\x00' +
                                                 b'\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00' +
                                                 b'\x00\x00\x00\x00\x00\x00\x00\x00', False, 53))

        # Bad packet
        self.assertIsNone(self.ipv6.parse_header(b'E\x00\x00\x00\x00\x08\x11@\xfd\x00\x00\x00\x00\x00\x00\x00' +
                                                 b'\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00' +
                                                 b'\x00\x00\x00\x00\x00\x00\x00\x00\x02', False, 53))

    def test_ipv6_make_header(self):
        # Normal
        self.assertEqual(self.ipv6.make_header(source_ip='fd00::1', destination_ip='fd00::2', traffic_class=0,
                                               flow_label=0, payload_len=8, next_header=17, hop_limit=64,
                                               exit_on_failure=True, exit_code=54),
                         b'`\x00\x00\x00\x00\x08\x11@\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02')
        # Bad source IP
        self.assertIsNone(self.ipv6.make_header(source_ip='fd00:::1', destination_ip='fd00::2', traffic_class=0,
                                                flow_label=0, payload_len=8, next_header=17, hop_limit=64,
                                                exit_on_failure=False, exit_code=54))
        # Bad destination IP
        self.assertIsNone(self.ipv6.make_header(source_ip='fd00::1', destination_ip='fd00:::2', traffic_class=0,
                                                flow_label=0, payload_len=8, next_header=17, hop_limit=64,
                                                exit_on_failure=False, exit_code=54))
        # Bad traffic class
        self.assertIsNone(self.ipv6.make_header(source_ip='fd00::1', destination_ip='fd00::2', traffic_class=123123123,
                                                flow_label=0, payload_len=8, next_header=17, hop_limit=64,
                                                exit_on_failure=False, exit_code=54))
        # Bad flow label
        self.assertIsNone(self.ipv6.make_header(source_ip='fd00::1', destination_ip='fd00::2', traffic_class=0,
                                                flow_label=123123123123, payload_len=8, next_header=17, hop_limit=64,
                                                exit_on_failure=False, exit_code=54))
        # Bad payload len
        self.assertIsNone(self.ipv6.make_header(source_ip='fd00::1', destination_ip='fd00::2', traffic_class=0,
                                                flow_label=0, payload_len=123123123123, next_header=17, hop_limit=64,
                                                exit_on_failure=False, exit_code=54))
        # Bad next header
        self.assertIsNone(self.ipv6.make_header(source_ip='fd00::1', destination_ip='fd00::2', traffic_class=0,
                                                flow_label=0, payload_len=8, next_header=123123123123123, hop_limit=64,
                                                exit_on_failure=False, exit_code=54))
        # Bad hop limit
        self.assertIsNone(self.ipv6.make_header(source_ip='fd00::1', destination_ip='fd00::2', traffic_class=0,
                                                flow_label=0, payload_len=8, next_header=17, hop_limit=123123123123123,
                                                exit_on_failure=False, exit_code=54))
    # endregion

    # region Test RawUDP methods
    def test_udp_parse_header(self):
        # Normal
        self.assertEqual(self.udp.parse_header(packet=b'\x14\xe9\x14\xe9\x00\x08\xdc\x07',
                                               exit_on_failure=True, exit_code=55),
                         {'source-port': 5353, 'destination-port': 5353, 'length': 8, 'checksum': 56327})
        # Bad packet length
        self.assertIsNone(self.udp.parse_header(packet=b'\x14\xe9\x14\xe9\x00\x08\xdc',
                                                exit_on_failure=False, exit_code=55))

    def test_udp_make_header(self):
        # Normal
        self.assertEqual(self.udp.make_header(source_port=5353, destination_port=5353, data_length=0,
                                              exit_on_failure=True, exit_code=56), b'\x14\xe9\x14\xe9\x00\x08\x00\x00')
        # Bad source port
        self.assertIsNone(self.udp.make_header(source_port=123123, destination_port=5353, data_length=0,
                                               exit_on_failure=False, exit_code=56))
        # Bad destination port
        self.assertIsNone(self.udp.make_header(source_port=5353, destination_port=123123, data_length=0,
                                               exit_on_failure=False, exit_code=56))
        # Bad data length
        self.assertIsNone(self.udp.make_header(source_port=5353, destination_port=5353, data_length=123123,
                                               exit_on_failure=False, exit_code=56))

    def test_udp_make_header_with_ipv6_checksum(self):
        # Normal
        self.assertEqual(self.udp.make_header_with_ipv6_checksum(ipv6_src='fd00::1', ipv6_dst='fd00::2', port_src=5353,
                                                                 port_dst=5353, payload_len=0, payload_data=b'',
                                                                 exit_on_failure=True, exit_code=57),
                         b'\x14\xe9\x14\xe9\x00\x08\xdc\x07')
        # Bad source IPv6 address
        self.assertIsNone(self.udp.make_header_with_ipv6_checksum(ipv6_src='fd00:::1', ipv6_dst='fd00::2',
                                                                  port_src=5353, port_dst=5353, payload_len=0,
                                                                  payload_data=b'', exit_on_failure=False,
                                                                  exit_code=57))
        # Bad destination IPv6 address
        self.assertIsNone(self.udp.make_header_with_ipv6_checksum(ipv6_src='fd00::1', ipv6_dst='fd00:::2',
                                                                  port_src=5353, port_dst=5353, payload_len=0,
                                                                  payload_data=b'', exit_on_failure=False,
                                                                  exit_code=57))
        # Bad source port
        self.assertIsNone(self.udp.make_header_with_ipv6_checksum(ipv6_src='fd00::1', ipv6_dst='fd00::2',
                                                                  port_src=123123, port_dst=5353, payload_len=0,
                                                                  payload_data=b'', exit_on_failure=False,
                                                                  exit_code=57))
        # Bad destination port
        self.assertIsNone(self.udp.make_header_with_ipv6_checksum(ipv6_src='fd00::1', ipv6_dst='fd00::2',
                                                                  port_src=5353, port_dst=123123, payload_len=0,
                                                                  payload_data=b'', exit_on_failure=False,
                                                                  exit_code=57))
        # Bad payload length
        self.assertIsNone(self.udp.make_header_with_ipv6_checksum(ipv6_src='fd00::1', ipv6_dst='fd00::2',
                                                                  port_src=5353, port_dst=5353, payload_len=123123,
                                                                  payload_data=b'', exit_on_failure=False,
                                                                  exit_code=57))
    # endregion
