# region Description
"""
RawIPv6.py: Unit tests for Raw-packet RawIPv6 class
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
from raw_packet.Utils.network import RawIPv6
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


# region Main class - RawEthernetTest
class RawIPv6Test(unittest.TestCase):

    # region Properties
    base: Base = Base()
    ipv6: RawIPv6 = RawIPv6()
    # endregion

    # region Test methods
    def test_make_random_ip(self):
        # Normal
        self.assertTrue(self.base.ipv6_address_validation(self.ipv6.make_random_ip(octets=3,
                                                                                   prefix='fd00::',
                                                                                   exit_on_failure=True,
                                                                                   exit_code=51)))
        # Bad prefix
        self.assertIsNone(self.ipv6.make_random_ip(octets=1, prefix='fd00:::', exit_on_failure=False, exit_code=51))
        # Bad octets count
        self.assertIsNone(self.ipv6.make_random_ip(octets=123, prefix='fd00::', exit_on_failure=False, exit_code=51))

    def test_pack_addr(self):
        # Normal
        self.assertEqual(self.ipv6.pack_addr(ipv6_address='3132:3334::1', exit_on_failure=True, exit_code=52),
                         b'1234\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01')
        # Bad IPv6 address
        self.assertIsNone(self.ipv6.pack_addr(ipv6_address='fd00:::1', exit_on_failure=False, exit_code=52))

    def test_parse_header(self):
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

    def test_make_header(self):
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
