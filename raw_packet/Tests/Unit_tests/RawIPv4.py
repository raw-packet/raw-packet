# region Description
"""
RawIPv4.py: Unit tests for Raw-packet RawIPv4 class
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
from raw_packet.Utils.network import RawIPv4
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
class RawIPv4Test(unittest.TestCase):

    # region Properties
    base: Base = Base()
    ipv4: RawIPv4 = RawIPv4()
    # endregion

    # region Test methods
    def test_make_random_ip(self):
        self.assertTrue(self.base.ip_address_validation(self.ipv4.make_random_ip()))

    def test_parse_header(self):
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

    def test_make_header(self):
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
