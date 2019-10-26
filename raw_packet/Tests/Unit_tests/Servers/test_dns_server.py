# region Description
"""
test_dns_server.py: Unit tests for Raw-packet DNS server
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
from raw_packet.Utils.tm import ThreadManager
from raw_packet.Servers.dns_server import RawDnsServer
# endregion

# region Import libraries
from dns.resolver import Resolver
from dns.rdatatype import A, AAAA
from subprocess import Popen, PIPE
from typing import List
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
class DnsServerTest(unittest.TestCase):

    # region Properties
    base: Base = Base()
    tm: ThreadManager = ThreadManager(2)
    dns_server: RawDnsServer = RawDnsServer()

    interface: str = 'lo'
    ipv4_address: str = '127.0.0.1'
    ipv6_address: str = '::1'
    listen_port: int = 53
    fake_ipv4_addresses: List[str] = ['192.168.0.123', '192.168.0.234']
    fake_ipv6_addresses: List[str] = ['fd00::123', 'fd00::234']
    fake_domains_regexp: List[str] = ['(test1|test2)\\.google.com', 'evil.com']
    fake_domains: List[str] = ['test1.google.com', 'test2.google.com', 'evil.com']
    no_such_domains: List[str] = ['gooogle.com', 'eviiil.com']
    real_domains: List[str] = ['www.google.com', 'google.com']
    success_domains: List[str] = ['evil.com']

    tm.add_task(dns_server.listen, interface, listen_port, None, None, None, False, fake_ipv4_addresses,
                fake_ipv6_addresses, fake_domains_regexp, no_such_domains, True, False, success_domains)

    test_ipv4_resolver = Resolver()
    test_ipv6_resolver = Resolver()
    test_ipv4_resolver.nameservers = [ipv4_address]
    test_ipv6_resolver.nameservers = [ipv6_address]
    test_ipv4_resolver.timeout = 3
    test_ipv6_resolver.timeout = 3
    result_addresses: List[str] = list()
    # endregion

    def test_resolve_ipv4_fake_domain(self):
        for fake_domain in self.fake_domains:
            answers = self.test_ipv6_resolver.query(fake_domain, A)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertEqual(self.result_addresses, self.fake_ipv4_addresses)
            self.result_addresses.clear()

    def test_resolve_ipv6_fake_domain(self):
        for fake_domain in self.fake_domains:
            answers = self.test_ipv6_resolver.query(fake_domain, AAAA)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertEqual(self.result_addresses, self.fake_ipv6_addresses)
            self.result_addresses.clear()

    def test_resolve_no_such_domain(self):
        for no_such_domain in self.no_such_domains:
            nslookup_process = Popen(['nslookup', no_such_domain, self.ipv6_address], stdout=PIPE, stderr=PIPE)
            (nslookup_stdout, nslookup_stderr) = nslookup_process.communicate()
            nslookup_stdout: str = nslookup_stdout.decode('utf-8')
            self.assertIn('server can\'t find ' + no_such_domain, nslookup_stdout)

    def test_resolve_ipv4_real_domain(self):
        for real_domain in self.real_domains:
            answers = self.test_ipv6_resolver.query(real_domain, A)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertNotEqual(self.result_addresses, self.fake_ipv4_addresses)
            self.assertNotEqual(len(self.result_addresses), 0)
            self.result_addresses.clear()

    def test_resolve_ipv6_real_domain(self):
        for real_domain in self.real_domains:
            answers = self.test_ipv6_resolver.query(real_domain, AAAA)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertNotEqual(self.result_addresses, self.fake_ipv6_addresses)
            self.assertNotEqual(len(self.result_addresses), 0)
            self.result_addresses.clear()

# endregion
