# region Description
"""
test_network.py: Unit tests for Raw-packet network classes
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from sys import path
from os.path import dirname, abspath
import unittest
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


# region Main class - NetworkTest
class NetworkTest(unittest.TestCase):

    # region Properties
    path.append(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawEthernet, RawARP, RawIPv4,  RawUDP, RawDNS, RawICMPv4, RawDHCPv4
    from raw_packet.Utils.network import RawIPv6, RawICMPv6, RawDHCPv6

    base: Base = Base()
    ethernet: RawEthernet = RawEthernet()
    arp: RawARP = RawARP()
    ipv4: RawIPv4 = RawIPv4()
    ipv6: RawIPv6 = RawIPv6()
    udp: RawUDP = RawUDP()
    dns: RawDNS = RawDNS()
    icmpv4: RawICMPv4 = RawICMPv4()
    dhcpv4: RawDHCPv4 = RawDHCPv4()
    icmpv6: RawICMPv6 = RawICMPv6()
    dhcpv6: RawDHCPv6 = RawDHCPv6()
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
        # Bad network type
        self.assertIsNone(self.ethernet.make_header('30:31:32:33:34:56', '36:37:38:39:40:41', 123123, False, 44))
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
        self.assertEqual(self.ipv4.make_header(source_ip='192.168.1.1', destination_ip='192.168.1.2', data_len=0,
                                               transport_protocol_len=8, transport_protocol_type=17, ttl=64,
                                               identification=1, exit_on_failure=True, exit_code=50),
                         b'E\x00\x00\x1c\x01\x00\x00\x00@\x11\xf6}\xc0\xa8\x01\x01\xc0\xa8\x01\x02')
        # Bad source IP
        self.assertIsNone(self.ipv4.make_header(source_ip='192.168.1.300', destination_ip='192.168.1.2', data_len=0,
                                                transport_protocol_len=8, transport_protocol_type=17, ttl=64,
                                                identification=1, exit_on_failure=False, exit_code=50))
        # Bad destination IP
        self.assertIsNone(self.ipv4.make_header(source_ip='192.168.1.1', destination_ip='192.168.1.400', data_len=0,
                                                transport_protocol_len=8, transport_protocol_type=17, ttl=64,
                                                identification=1, exit_on_failure=False, exit_code=50))
        # Bad identification
        self.assertIsNone(self.ipv4.make_header(source_ip='192.168.1.1', destination_ip='192.168.1.2', data_len=0,
                                                transport_protocol_len=8, transport_protocol_type=17, ttl=64,
                                                identification=123123, exit_on_failure=False, exit_code=50))
        # Bad data length
        self.assertIsNone(self.ipv4.make_header(source_ip='192.168.1.1', destination_ip='192.168.1.2', data_len=123123,
                                                transport_protocol_len=8, transport_protocol_type=17, ttl=64,
                                                identification=1, exit_on_failure=False, exit_code=50))
        # Bad transport protocol header length
        self.assertIsNone(self.ipv4.make_header(source_ip='192.168.1.1', destination_ip='192.168.1.2', data_len=0,
                                                transport_protocol_len=123123, transport_protocol_type=17, ttl=64,
                                                identification=1, exit_on_failure=False, exit_code=50))
        # Bad transport protocol type
        self.assertIsNone(self.ipv4.make_header(source_ip='192.168.1.1', destination_ip='192.168.1.2', data_len=0,
                                                transport_protocol_len=8, transport_protocol_type=123123, ttl=64,
                                                identification=1, exit_on_failure=False, exit_code=50))
        # Bad ttl
        self.assertIsNone(self.ipv4.make_header(source_ip='192.168.1.1', destination_ip='192.168.1.2', data_len=0,
                                                transport_protocol_len=8, transport_protocol_type=17, ttl=123123,
                                                identification=1, exit_on_failure=False, exit_code=50))
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

    # region Test RawDNS methods
    def test_dns_get_top_level_domain(self):
        # Normal
        self.assertEqual(self.dns.get_top_level_domain(name='www.test.com'), 'test.com')

        # Bad name
        self.assertEqual(self.dns.get_top_level_domain(name='test'), 'test')

    def test_dns_pack_dns_name(self):
        # Normal
        self.assertEqual(self.dns.pack_dns_name(name='test.com', exit_on_failure=True, exit_code=65),
                         b'\x04test\x03com\x00')
        # Bad name
        self.assertIsNone(self.dns.pack_dns_name(name='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
                                                      '.com', exit_on_failure=False, exit_code=65))

    def test_dns_parse_packet(self):
        self.assertEqual(self.dns.parse_packet(packet=b'\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' +
                                                      b'\x04test\x03com\x00\x00\x01\x00\x01\x04test\x03com\x00' +
                                                      b'\x00\x01\x00\x01\x00\x00\xff\xff\x00\x04\xc0\xa8\x01\x01',
                                               exit_on_failure=True, exit_code=67),
                         {'additional-rrs': 0, 'answer-rrs': 1, 'authority-rrs': 0, 'questions': 1, 'flags': 33152,
                          'transaction-id': 1,
                          'answers': [
                              {'address': '192.168.1.1',
                               'class': 1,
                               'name': 'test.com.',
                               'ttl': 65535,
                               'type': 1}],
                          'queries': [{'class': 1,
                                       'name': 'test.com.',
                                       'type': 1}]})

    def test_dns_unpack_dns_name(self):
        self.assertEqual(self.dns.unpack_dns_name(packed_name=b'\x03www\x04test\x03com\x00'), 'www.test.com.')
        self.assertEqual(self.dns.unpack_dns_name(packed_name=b'\x04mail\xc0\x11', name='pop3.test.com'),
                         'mail.test.com')
        self.assertEqual(self.dns.unpack_dns_name(packed_name=b'\xc0\x10', name='test.com'), 'test.com')
        self.assertEqual(self.dns.unpack_dns_name(packed_name=b'\x03www\xc0\x0c', name='test.com'), 'www.test.com')

    def test_dns_make_ipv4_request_packet(self):
        # Normal
        self.assertEqual(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                           ethernet_dst_mac='01:23:45:67:89:0b',
                                                           ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                           ip_ttl=64, ip_ident=1,
                                                           udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                           queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                           flags=0),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x00E\x00\x006\x01\x00\x00\x00@\x11\xf6c\xc0\xa8\x01\x01' +
                         b'\xc0\xa8\x01\x02\x14\xe9\x005\x00"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' +
                         b'\x04test\x03com\x00\x00\x01\x00\x01')
        # Bad source MAC address
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:890ab',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad destination MAC address
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:890ab',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad source IPv4 address
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.300', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad destination IPv4 address
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.400',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad source UDP port
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=123123, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad destination UDP port
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=123123, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad transaction id
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=123123123,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad query type
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 123123, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad query class
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 123123, 'name': 'test.com'}],
                                                            flags=0))
        # Bad flags
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=123123))
        # Bad queries
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad queries
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad queries
        self.assertIsNone(self.dns.make_ipv4_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='192.168.1.1', ip_dst='192.168.1.2',
                                                            ip_ttl=64, ip_ident=1,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'class': 1, 'type': 1}],
                                                            flags=0))

    def test_dns_make_ipv6_request_packet(self):
        # Normal
        self.assertEqual(self.dns.make_ipv6_request_packet(ethernet_src_mac='01:23:45:67:89:0a', ethernet_dst_mac='01:23:45:67:89:0b',
                                                           ip_src='fd00::1', ip_dst='fd00::2', ip_ttl=64,
                                                           udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                           queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                           flags=0),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x86\xdd`\x00\x00\x00\x00"\x11@\xfd\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x02\x14\xe9\x005\x00"B)\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' +
                         b'\x04test\x03com\x00\x00\x01\x00\x01')
        # Bad source IPv6 address
        self.assertIsNone(self.dns.make_ipv6_request_packet(ethernet_src_mac='01:23:45:67:89:0a', ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='fd00:::1', ip_dst='fd00::2', ip_ttl=64,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))
        # Bad destination IPv6 address
        self.assertIsNone(self.dns.make_ipv6_request_packet(ethernet_src_mac='01:23:45:67:89:0a', ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ip_src='fd00::1', ip_dst='fd00:::2', ip_ttl=64,
                                                            udp_src_port=5353, udp_dst_port=53, transaction_id=1,
                                                            queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                            flags=0))

    def test_dns_make_response_packet(self):
        # Normal IPv4 response
        self.assertEqual(self.dns.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                       ethernet_dst_mac='01:23:45:67:89:0b',
                                                       ip_src='192.168.1.1', ip_dst='192.168.1.2', ip_ttl=64,
                                                       ip_ident=1, udp_src_port=53, udp_dst_port=5353, transaction_id=1,
                                                       flags=0x8180,
                                                       queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                       answers_address=[{'name': 'test.com', 'type': 1, 'class': 1,
                                                                         'ttl': 65535, 'address': '192.168.1.1'}],
                                                       name_servers={}, exit_on_failure=True),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x00E\x00\x00F\x01\x00\x00\x00@\x11\xf6S\xc0\xa8\x01\x01' +
                         b'\xc0\xa8\x01\x02\x005\x14\xe9\x002\xb5{\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' +
                         b'\x04test\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\xff\xff\x00\x04\xc0' +
                         b'\xa8\x01\x01')
        # Normal IPv6 response
        self.assertEqual(self.dns.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                       ethernet_dst_mac='01:23:45:67:89:0b',
                                                       ip_src='fd00::1', ip_dst='fd00::2', ip_ttl=64, ip_ident=1,
                                                       udp_src_port=53, udp_dst_port=5353, transaction_id=1,
                                                       flags=0x8180,
                                                       queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                       answers_address=[{'name': 'test.com', 'type': 28, 'class': 1,
                                                                         'ttl': 65535, 'address': 'fd00::1'}],
                                                       name_servers={}, exit_on_failure=True),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x86\xdd`\x00\x00\x00\x00>\x11@\xfd\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x02\x005\x14\xe9\x00>\x034\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x04' +
                         b'test\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\xff\xff\x00\x10\xfd\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
        # Bad MAC address
        self.assertIsNone(self.dns.make_response_packet(ethernet_src_mac='01:23:45:67:890ab',
                                                        ethernet_dst_mac='01:23:45:67:89:0b',
                                                        ip_src='fd00::1', ip_dst='fd00::2', ip_ttl=64, ip_ident=1,
                                                        udp_src_port=53, udp_dst_port=5353, transaction_id=1, flags=0,
                                                        queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                        answers_address=[{'name': 'test.com', 'type': 28, 'class': 1,
                                                                          'ttl': 65535, 'address': 'fd00::1'}],
                                                        name_servers={}, exit_on_failure=False))
        # Bad IP address
        self.assertIsNone(self.dns.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                        ethernet_dst_mac='01:23:45:67:89:0b',
                                                        ip_src='fd00:::1', ip_dst='fd00::2', ip_ttl=64, ip_ident=1,
                                                        udp_src_port=53, udp_dst_port=5353, transaction_id=1, flags=0,
                                                        queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                        answers_address=[{'name': 'test.com', 'type': 28, 'class': 1,
                                                                          'ttl': 65535, 'address': 'fd00::1'}],
                                                        name_servers={}, exit_on_failure=False))
        # Bad UDP port
        self.assertIsNone(self.dns.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                        ethernet_dst_mac='01:23:45:67:89:0b',
                                                        ip_src='fd00::1', ip_dst='fd00::2', ip_ttl=64, ip_ident=1,
                                                        udp_src_port=123123, udp_dst_port=5353, transaction_id=1, flags=0,
                                                        queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                        answers_address=[{'name': 'test.com', 'type': 28, 'class': 1,
                                                                          'ttl': 65535, 'address': 'fd00::1'}],
                                                        name_servers={}, exit_on_failure=False))
        # Bad IPv4 address in answer
        self.assertIsNone(self.dns.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                        ethernet_dst_mac='01:23:45:67:89:0b',
                                                        ip_src='fd00::1', ip_dst='fd00::2', ip_ttl=64, ip_ident=1,
                                                        udp_src_port=53, udp_dst_port=5353, transaction_id=1, flags=0,
                                                        queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                        answers_address=[{'name': 'test.com', 'type': 1, 'class': 1,
                                                                          'ttl': 65535, 'address': '192.168.1.300'}],
                                                        name_servers={}, exit_on_failure=False))
        # Bad IPv6 address in answer
        self.assertIsNone(self.dns.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                        ethernet_dst_mac='01:23:45:67:89:0b',
                                                        ip_src='fd00::1', ip_dst='fd00::2', ip_ttl=64, ip_ident=1,
                                                        udp_src_port=53, udp_dst_port=5353, transaction_id=1, flags=0,
                                                        queries=[{'type': 1, 'class': 1, 'name': 'test.com'}],
                                                        answers_address=[{'name': 'test.com', 'type': 28, 'class': 1,
                                                                          'ttl': 65535, 'address': 'fd00:::1'}],
                                                        name_servers={}, exit_on_failure=False))
        # endregion
    # endregion

    # region Test RawICMPv4 methods
    def test_icmpv4_make_host_unreachable_packet(self):
        # Normal
        self.assertEqual(self.icmpv4.make_host_unreachable_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                                  ethernet_dst_mac='01:23:45:67:89:0b',
                                                                  ip_src='192.168.0.1', ip_dst='192.168.0.2',
                                                                  ip_ident=1),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x00E\x00\x000\x01\x00\x00\x00@\x01\xf8y\xc0\xa8\x00' +
                         b'\x01\xc0\xa8\x00\x02\x03\x01\xfc\xfe\x00\x00\x00\x00E\x00\x00\x1c\x01\x00\x00\x00@\x01' +
                         b'\xf8\x8d\xc0\xa8\x00\x02\xc0\xa8\x00\x01')
        # Bad MAC address
        self.assertIsNone(self.icmpv4.make_host_unreachable_packet(ethernet_src_mac='01:23:45:67:89:0ab',
                                                                   ethernet_dst_mac='01:23:45:67:89:0b',
                                                                   ip_src='192.168.0.1', ip_dst='192.168.0.2',
                                                                   ip_ident=1))
        # Bad IP address
        self.assertIsNone(self.icmpv4.make_host_unreachable_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                                   ethernet_dst_mac='01:23:45:67:89:0b',
                                                                   ip_src='192.168.0.1111', ip_dst='192.168.0.2',
                                                                   ip_ident=1))

    def test_icmpv4_make_udp_port_unreachable_packet(self):
        # Normal
        self.assertEqual(self.icmpv4.make_udp_port_unreachable_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                                      ethernet_dst_mac='01:23:45:67:89:0b',
                                                                      ip_src='192.168.0.1', ip_dst='192.168.0.2',
                                                                      udp_src_port=5353, udp_dst_port=5353,
                                                                      ip_ident=1),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x00E\x00\x008\x01\x00\x00\x00@\x01\xf8q\xc0\xa8\x00\x01' +
                         b'\xc0\xa8\x00\x02\x03\x03\xd3"\x00\x00\x00\x00E\x00\x00$\x01\x00\x00\x00@\x11\xf8u\xc0\xa8' +
                         b'\x00\x02\xc0\xa8\x00\x01\x14\xe9\x14\xe9\x00\x08\x00\x00')

    def test_icmpv4_make_ping_request_packet(self):
        # Normal
        self.assertEqual(self.icmpv4.make_ping_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                              ethernet_dst_mac='01:23:45:67:89:0b',
                                                              ip_src='192.168.0.1', ip_dst='192.168.0.2',
                                                              ip_ident=1, data=b'0123456789'),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x00E\x00\x00&\x01\x00\x00\x00@\x01\xf8\x83\xc0\xa8\x00' +
                         b'\x01\xc0\xa8\x00\x02\x08\x00\xf2\xf5\x00\x00\x00\x000123456789')

    def test_icmpv4_make_redirect_packet(self):
        # Normal
        self.assertEqual(self.icmpv4.make_redirect_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                          ethernet_dst_mac='01:23:45:67:89:0b',
                                                          ip_src='192.168.0.1', ip_dst='192.168.0.2',
                                                          ip_ttl=64, ip_ident=1,
                                                          gateway_address='192.168.0.1',
                                                          payload_ip_src='192.168.0.1',
                                                          payload_ip_dst='192.168.0.2'),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x00E\x00\x008\x01\x00\x00\x00@\x01\xf8q\xc0\xa8\x00\x01' +
                         b'\xc0\xa8\x00\x02\x05\x019\xe3\xc0\xa8\x00\x01E\x00\x00\x1c\x01\x00\x00\x00@\x11\xf8}\xc0' +
                         b'\xa8\x00\x01\xc0\xa8\x00\x02\x005\x005\x00\x08\x00\x00')
        # Bad gateway address
        self.assertIsNone(self.icmpv4.make_redirect_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                           ethernet_dst_mac='01:23:45:67:89:0b',
                                                           ip_src='192.168.0.1', ip_dst='192.168.0.2',
                                                           ip_ttl=64, ip_ident=1,
                                                           gateway_address='192.168.0.1111',
                                                           payload_ip_src='192.168.0.1',
                                                           payload_ip_dst='192.168.0.2'))
        # Bad payload IP address
        self.assertIsNone(self.icmpv4.make_redirect_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                           ethernet_dst_mac='01:23:45:67:89:0b',
                                                           ip_src='192.168.0.1', ip_dst='192.168.0.2',
                                                           ip_ttl=64, ip_ident=1,
                                                           gateway_address='192.168.0.1',
                                                           payload_ip_src='192.168.0.1111',
                                                           payload_ip_dst='192.168.0.2'))
    # endregion

    # region Test RawDHCPv4 methods
    def test_dhcpv4_discover_packet(self):
        # Normal
        self.assertEqual(self.dhcpv4.make_discover_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                          client_mac='01:23:45:67:89:0a',
                                                          ip_ident=1, transaction_id=1,
                                                          host_name='dhcp.discover.test',
                                                          exit_on_failure=True,
                                                          exit_code=76),
                         b'\xff\xff\xff\xff\xff\xff\x01#Eg\x89\n\x08\x00E\x00\x02<\x01\x00\x00\x00@\x11w\xb2\x00' +
                         b'\x00\x00\x00\xff\xff\xff\xff\x00D\x00C\x02(\x00\x00\x01\x01\x06\x00\x00\x00\x00\x01\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#Eg\x89' +
                         b'\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00c\x82Sc5\x01\x01\x0c\x12dhcp.discover.test7\xfe\x01\x02\x03\x04\x05' +
                         b'\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c' +
                         b'\x1d\x1e\x1f !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefg' +
                         b'hijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e' +
                         b'\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4' +
                         b'\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba' +
                         b'\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0' +
                         b'\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6' +
                         b'\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc' +
                         b'\xfd\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00')

    def test_dhcpv4_make_request_packet(self):
        # Normal
        self.assertEqual(self.dhcpv4.make_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                         client_mac='01:23:45:67:89:0a',
                                                         ip_ident=1, transaction_id=1,
                                                         requested_ip='192.168.1.1',
                                                         host_name='dhcp.request.test',
                                                         exit_on_failure=True,
                                                         exit_code=77),
                         b'\xff\xff\xff\xff\xff\xff\x01#Eg\x89\n\x08\x00E\x00\x01J\x01\x00\x00\x00@\x11x\xa4\x00' +
                         b'\x00\x00\x00\xff\xff\xff\xff\x00D\x00C\x016\x00\x00\x01\x01\x06\x00\x00\x00\x00\x01\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#Eg\x89' +
                         b'\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00c\x82Sc5\x01\x032\x04\xc0\xa8\x01\x01\x0c\x11dhcp.request.test7\x07' +
                         b'\x01\x02\x03\x06\x1c\x0f\x1a\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_dhcpv4_make_response_packet(self):
        # DHCPv4 Offer
        self.assertEqual(self.dhcpv4.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                          ethernet_dst_mac='01:23:45:67:89:0b',
                                                          ip_src='192.168.1.1', ip_ident=1, transaction_id=1,
                                                          dhcp_message_type=2, your_client_ip='192.168.1.2',
                                                          exit_on_failure=True,
                                                          exit_code=78),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x00E\x00\x01F\x01\x00\x00\x00@\x11\xb6\xfe\xc0\xa8\x01' +
                         b'\x01\xff\xff\xff\xff\x00C\x00D\x012\x00\x00\x02\x01\x06\x00\x00\x00\x00\x01\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\xc0\xa8\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01#Eg\x89\x0b\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00c\x82Sc5\x01\x026\x04\xc0\xa8\x01\x013\x04\x00\x00\xff\xff\x01\x04\xff\xff\xff' +
                         b'\x00\x03\x04\xc0\xa8\x01\x01\x06\x04\xc0\xa8\x01\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        # DHCPv4 ACK
        self.assertEqual(self.dhcpv4.make_response_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                          ethernet_dst_mac='01:23:45:67:89:0b',
                                                          ip_src='192.168.1.1', ip_ident=1, transaction_id=1,
                                                          dhcp_message_type=5, your_client_ip='192.168.1.2',
                                                          exit_on_failure=True,
                                                          exit_code=78),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x00E\x00\x01F\x01\x00\x00\x00@\x11\xb6\xfe\xc0\xa8\x01' +
                         b'\x01\xff\xff\xff\xff\x00C\x00D\x012\x00\x00\x02\x01\x06\x00\x00\x00\x00\x01\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\xc0\xa8\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01#Eg\x89\x0b\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00c\x82Sc5\x01\x056\x04\xc0\xa8\x01\x013\x04\x00\x00\xff\xff\x01\x04\xff\xff\xff' +
                         b'\x00\x03\x04\xc0\xa8\x01\x01\x06\x04\xc0\xa8\x01\x01\xff\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    # endregion

    # region Test RawICMPv6 methods
    def test_icmpv6_make_option(self):
        # Normal
        self.assertEqual(self.icmpv6.make_option(option_type=1, option_value=b'test_option_value'),
                         b'\x01\x03\x00\x00\x00\x00\x00test_option_value')

    def test_icmpv6_make_router_solicit_packet(self):
        # Normal
        self.assertEqual(self.icmpv6.make_router_solicit_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                                ethernet_dst_mac='33:33:00:00:00:02',
                                                                ipv6_src='fd00::1', ipv6_dst='fd00::2',
                                                                ipv6_flow=0x835d1,
                                                                need_source_link_layer_address=True,
                                                                source_link_layer_address=None),
                         b'33\x00\x00\x00\x02\x01#Eg\x89\n\x86\xdd`\x085\xd1\x00\x10:\xff\xfd\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x02\x85\x00\xb0\x1a\x00\x00\x00\x00\x01\x01\x01#Eg\x89\n')

    def test_icmpv6_make_router_advertisement_packet(self):
        # Normal
        self.assertEqual(self.icmpv6.make_router_advertisement_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                                      ethernet_dst_mac='01:23:45:67:89:0b',
                                                                      ipv6_src='fd00::1', ipv6_dst='fd00::2',
                                                                      dns_address='fd00::1', domain_search='test.local',
                                                                      prefix='fd00::/64'),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x86\xdd`\x0bGU\x00\x80:\xff\xfd\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x02\x86\x00\xb3>@\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x04@\xc0\xff\xff' +
                         b'\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x01\x01\x01#Eg\x89\n\x05\x01\x00\x00\x00\x00\x05\xdc\x19\x03\x00\x00\x00' +
                         b'\x00\x17p\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1f\x04\x00\x00' +
                         b'\x00\x00\x17p\x04test\x05local\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x01' +
                         b'\x00\x00\x00\x00\xea`')

    def test_icmpv6_make_neighbor_solicitation_packet(self):
        # Normal
        self.assertEqual(self.icmpv6.make_neighbor_solicitation_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                                       ipv6_src='fd00::1'),
                         b'33\x00\x00\x00\x01\x01#Eg\x89\n\x86\xdd`\x00\x00\x00\x00 :\xff\xfd\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x01\x87\x00\xac\x05\x00\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x01\x02\x01\x01#Eg\x89\n')

    def test_icmpv6_make_neighbor_advertisement_packet(self):
        # Normal
        self.assertEqual(self.icmpv6.make_neighbor_advertisement_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                                        ipv6_src='fd00::1',
                                                                        target_ipv6_address='fd00::2'),
                         b'33\x00\x00\x00\x01\x01#Eg\x89\n\x86\xdd`\x00\x00\x00\x00 :\xff\xfd\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x01\x88\x00\x8d\x06 \x00\x00\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x02\x02\x01\x01#Eg\x89\n')

    def test_icmpv6_make_echo_request_packet(self):
        # Normal
        self.assertEqual(self.icmpv6.make_echo_request_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                              ethernet_dst_mac='01:23:45:67:89:0b',
                                                              ipv6_src='fd00::1', ipv6_dst='fd00::2',
                                                              id=1, sequence=1),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x86\xdd`\x00\x00\x00\x00@:\xff\xfd\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x02\x80\x00\x8ek\x00\x01\x00\x01\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c' +
                         b'\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ' +
                         b'!"#$%&\'()*+,-./01234567')

    def test_icmpv6_make_echo_reply_packet(self):
        # Normal
        self.assertEqual(self.icmpv6.make_echo_reply_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ipv6_src='fd00::1', ipv6_dst='fd00::2',
                                                            id=1, sequence=1),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x86\xdd`\x00\x00\x00\x00@:\xff\xfd\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x02\x81\x00\x8dk\x00\x01\x00\x01\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c' +
                         b'\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ' +
                         b'!"#$%&\'()*+,-./01234567')
    # endregion

    # region Test RawDHCPv6 methods
    def test_dhcpv6_make_option(self):
        # Normal
        self.assertEqual(self.dhcpv6._make_duid(mac_address='01:23:45:67:89:0a'),
                         b'\x00\x03\x00\x01\x01#Eg\x89\n')

    def test_dhcpv6_make_solicit_packet(self):
        # Normal
        self.assertEqual(self.dhcpv6.make_solicit_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                         ipv6_src='fd00::1',
                                                         transaction_id=1,
                                                         client_mac_address='01:23:45:67:89:0a',
                                                         option_request_list=[23, 24]),
                         b'33\x00\x01\x00\x02\x01#Eg\x89\n\x86\xdd`\x00\x00\x00\x00H\x11@\xfd\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x01\x00\x02\x02"\x02#\x00H.\x01\x01\x00\x00\x01\x00\x03\x00\x18\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x00' +
                         b'\x00\x00\x08\x00\x02\x00\x00\x00\x01\x00\n\x00\x03\x00\x01\x01#Eg\x89\n\x00\x06\x00\x04' +
                         b'\x00\x17\x00\x18')

    def test_dhcpv6_make_relay_forw_packet(self):
        # Normal
        self.assertEqual(self.dhcpv6.make_relay_forw_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                            ethernet_dst_mac='01:23:45:67:89:0b',
                                                            ipv6_src='fd00::1', ipv6_dst='fd00::2', ipv6_flow=1,
                                                            hop_count=10, link_addr='fd00::2',
                                                            peer_addr='fd00::3'),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x86\xdd`\x00\x00\x01\x00*\x11@\xfd\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x02\x02"\x02#\x00*\xfb?\x0c\n\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x02\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03')

    def test_dhcpv6_make_advertise_packet(self):
        # Normal
        self.assertEqual(self.dhcpv6.make_advertise_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                           ethernet_dst_mac='01:23:45:67:89:0b',
                                                           ipv6_src='fd00::1', ipv6_dst='fd00::2',
                                                           transaction_id=1,
                                                           dns_address='fd00::1',
                                                           domain_search='test.local',
                                                           ipv6_address='fd00::2'),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x86\xdd`\n\x1b\x82\x00\x84\x11@\xfd\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x02\x02#\x02"\x00\x84n\xf4\x02\x00\x00\x01\x00\x01\x00\n\x00\x03\x00\x01\x01#Eg' +
                         b'\x89\x0b\x00\x02\x00\n\x00\x03\x00\x01\x01#Eg\x89\n\x00\x14\x00\x00\x00\x17\x00\x10\xfd' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x18\x00\x0c\x04test\x05' +
                         b'local\x00\x00R\x00\x04\x00\x00\x00<\x00\x03\x00(\x00\x00\x00\x01\x00\x00T`\x00\x00\x87' +
                         b'\x00\x00\x05\x00\x18\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\xff' +
                         b'\xff\xff\xff\xff\xff\xff\xff')

    def test_dhcpv6_make_reply_packet(self):
        # Normal
        self.assertEqual(self.dhcpv6.make_reply_packet(ethernet_src_mac='01:23:45:67:89:0a',
                                                       ethernet_dst_mac='01:23:45:67:89:0b',
                                                       ipv6_src='fd00::1', ipv6_dst='fd00::2',
                                                       transaction_id=1,
                                                       dns_address='fd00::1',
                                                       domain_search='test.local',
                                                       ipv6_address='fd00::2'),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x86\xdd`\n\x1b\x82\x00\x84\x11@\xfd\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                         b'\x00\x00\x02\x02#\x02"\x00\x84i\xf4\x07\x00\x00\x01\x00\x01\x00\n\x00\x03\x00\x01\x01#Eg' +
                         b'\x89\x0b\x00\x02\x00\n\x00\x03\x00\x01\x01#Eg\x89\n\x00\x14\x00\x00\x00\x17\x00\x10\xfd' +
                         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x18\x00\x0c\x04test\x05' +
                         b'local\x00\x00R\x00\x04\x00\x00\x00<\x00\x03\x00(\x00\x00\x00\x01\x00\x00T`\x00\x00\x87' +
                         b'\x00\x00\x05\x00\x18\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\xff' +
                         b'\xff\xff\xff\xff\xff\xff\xff')
    # endregion

# endregion
