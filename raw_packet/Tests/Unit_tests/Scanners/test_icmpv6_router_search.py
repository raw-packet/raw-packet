# region Description
"""
test_icmpv6_router_search.py: Unit tests for ICMPv6 Search IPv6 Router
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Scanners.icmpv6_router_search import ICMPv6RouterSearch
from raw_packet.Tests.Unit_tests.variables import Variables
from unittest import TestCase
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
class ICMPv6RouterSearchTest(TestCase):

    # region Properties
    variables: Variables = Variables()
    icmpv6_search: ICMPv6RouterSearch = ICMPv6RouterSearch(network_interface=variables.your.network_interface)
    # endregion

    def test01_search_router(self):
        ipv6_router_info = self.icmpv6_search.search(timeout=3, retry=3, exit_on_failure=False)
        self.assertIsNotNone(ipv6_router_info)
        self.assertIn('router_mac_address', ipv6_router_info)
        self.assertIn('router_ipv6_address', ipv6_router_info)
        self.assertIn('dns-server', ipv6_router_info)
        self.assertIn('vendor', ipv6_router_info)
        self.assertEqual(ipv6_router_info['router_mac_address'], self.variables.router.mac_address)
        self.assertEqual(ipv6_router_info['router_ipv6_address'], self.variables.router.ipv6_link_address)
        self.assertEqual(ipv6_router_info['dns-server'], self.variables.router.ipv6_link_address)
        self.assertIn(self.variables.router.vendor, ipv6_router_info['vendor'])

# endregion
