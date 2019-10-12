# region Description
"""
RawARP.py: Unit tests for Raw-packet RawARP class
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
from raw_packet.Utils.network import RawARP
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
class RawARPTest(unittest.TestCase):

    # region Properties
    arp: RawARP = RawARP()
    # endregion

    # region Test methods
    def test_parse_packet(self):
        # Normal packet
        self.assertEqual(self.arp.parse_packet(b'\x00\x01\x08\x00\x06\x04\x00\x01\x01#Eg\x89\n\xc0\xa8\x01\x01\x01' +
                                               b'#Eg\x89\x0b\xc0\xa8\x01\x02', True, 45),
                         {'hardware-type': 1, 'protocol-type': 2048, 'hardware-size': 6, 'protocol-size': 4,
                          'opcode': 1, 'sender-mac': '01:23:45:67:89:0a', 'sender-ip': '192.168.1.1',
                          'target-mac': '01:23:45:67:89:0b', 'target-ip': '192.168.1.2'})
        # Bad packet
        self.assertIsNone(self.arp.parse_packet(b'\x00\x01\x08\x00\x06\x04\x00\x01\x01#Eg\x89\n\xc0\xa8\x01\x01\x01' +
                                                b'#Eg\x89\x0b\xc0\xa8\x01\x02\x03', False, 45))

    def test_make_packet(self):
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

    def test_make_request(self):
        # Normal
        self.assertEqual(self.arp.make_request('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                               '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', True, 47),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x01#Eg\x89\n' +
                         b'\xc0\xa8\x01\x01\x01#Eg\x89\x0b\xc0\xa8\x01\x02')

    def test_make_response(self):
        # Normal
        self.assertEqual(self.arp.make_response('01:23:45:67:89:0a', '01:23:45:67:89:0b', '01:23:45:67:89:0a',
                                                '192.168.1.1', '01:23:45:67:89:0b', '192.168.1.2', True, 48),
                         b'\x01#Eg\x89\x0b\x01#Eg\x89\n\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\x01#Eg\x89\n' +
                         b'\xc0\xa8\x01\x01\x01#Eg\x89\x0b\xc0\xa8\x01\x02')

    # endregion
