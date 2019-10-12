# region Description
"""
RawEthernet.py: Unit tests for Raw-packet RawEthernet class
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
from raw_packet.Utils.network import RawEthernet
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
class RawEthernetTest(unittest.TestCase):

    # region Properties
    base: Base = Base()
    ethernet: RawEthernet = RawEthernet()
    # endregion

    # region Test methods
    def test_init(self):
        self.assertIn('00:18:de', self.ethernet.macs)

    def test_make_random_mac(self):
        self.assertTrue(self.base.mac_address_validation(self.ethernet.make_random_mac()))

    def test_convert_mac(self):
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

    def test_get_mac_prefix(self):
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

    def test_parse_header(self):
        # Normal packet
        self.assertEqual(self.ethernet.parse_header(b'6789@A012345\x08\x00', True, 43),
                         {'destination': '36:37:38:39:40:41', 'source': '30:31:32:33:34:35', 'type': 2048})
        # Bad packet
        self.assertIsNone(self.ethernet.parse_header(b'6789@A012345\x08\x00\x01', False, 43))

    def test_make_header(self):
        # MAC addresses string
        self.assertEqual(self.ethernet.make_header('30:31:32:33:34:35', '36:37:38:39:40:41', 2048, True, 44),
                         b'6789@A012345\x08\x00')
        # Bad first MAC address bytes
        self.assertIsNone(self.ethernet.make_header('30:31:32:33:34567', '36:37:38:39:40:41', 2048, False, 44))
        # Bad second MAC address bytes
        self.assertIsNone(self.ethernet.make_header('30:31:32:33:34:56', '36:37:38:39:40123', 2048, False, 44))
    # endregion
