# region Description
"""
test_dns_server.py: Unit tests for Raw-packet DNS server
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from dns.resolver import Resolver
from dns.rdatatype import A, AAAA, NS, MX
from subprocess import run, PIPE
from typing import List, Dict
from json import dump
from os import remove
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
class DnsServerTest(unittest.TestCase):

    # region Properties
    path.append(dirname(dirname(dirname(dirname(dirname(abspath(__file__)))))))
    from raw_packet.Utils.base import Base
    from raw_packet.Utils.tm import ThreadManager
    from raw_packet.Servers.dns_server import RawDnsServer

    base: Base = Base()
    tm: ThreadManager = ThreadManager(2)
    dns_server: RawDnsServer = RawDnsServer()

    interface: str = 'lo'
    ipv4_address: str = '127.0.0.1'
    ipv6_address: str = '::1'
    listen_port: int = 53
    fake_ipv4_addresses: List[str] = ['192.168.0.123', '192.168.0.234']
    fake_ipv6_addresses: List[str] = ['fd00::123', 'fd00::234']
    fake_ns_servers: List[str] = ['ns1.test.com', 'ns2.test.com']
    fake_mx_servers: List[str] = ['mail1.test.com', 'mail2.test.com']
    fake_domains_regexp: List[str] = ['(test1|test2)\\.google.com', 'evil.com']
    fake_domains: List[str] = ['test1.google.com', 'test2.google.com', 'evil.com']
    no_such_domains: List[str] = ['gooogle.com', 'eviiil.com']
    real_domains: List[str] = ['www.google.com', 'google.com']
    success_domains: List[str] = ['evil.com']

    config_file_name: str = 'config.json'
    config_fake_domains: List[str] = ['test1.com', 'www.test1.com']
    config_success_domains: List[str] = ['test2.com', 'www.test2.com']
    config_no_such_domains: List[str] = ['test3.com', 'www.test3.com']
    config_content: Dict = {'.*test1.com': {'A': fake_ipv4_addresses[0], 'AAAA': fake_ipv6_addresses,
                                            'NS': fake_ns_servers[0], 'MX': fake_mx_servers},
                            '.*test2.com': {'success': True, 'A': 'my ipv4 address', 'AAAA': 'my ipv6 address'},
                            '.*test3.com': {'no such domain': True}}
    with open(config_file_name, 'w') as config_file:
        dump(config_content, config_file)

    tm.add_task(dns_server.listen, interface, listen_port, None, None, None, False,
                fake_ipv4_addresses, fake_ipv6_addresses, fake_domains_regexp, no_such_domains,
                True, False, success_domains, config_file_name)

    test_ipv4_resolver = Resolver()
    test_ipv6_resolver = Resolver()
    test_ipv4_resolver.nameservers = [ipv4_address]
    test_ipv6_resolver.nameservers = [ipv6_address]
    test_ipv4_resolver.timeout = 3
    test_ipv6_resolver.timeout = 3
    result_addresses: List[str] = list()
    # endregion

    def test01_resolve_ipv4_fake_domain(self):
        for fake_domain in self.fake_domains:
            answers = self.test_ipv6_resolver.query(fake_domain, A)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertEqual(self.result_addresses, self.fake_ipv4_addresses)
            self.result_addresses.clear()

    def test02_resolve_ipv6_fake_domain(self):
        for fake_domain in self.fake_domains:
            answers = self.test_ipv6_resolver.query(fake_domain, AAAA)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertEqual(self.result_addresses, self.fake_ipv6_addresses)
            self.result_addresses.clear()

    def test03_resolve_no_such_domain(self):
        for no_such_domain in self.no_such_domains:
            nslookup_process = run(['nslookup ' + no_such_domain + ' ' + self.ipv6_address], stdout=PIPE, shell=True)
            nslookup_stdout: str = nslookup_process.stdout.decode('utf-8')
            self.assertIn('server can\'t find ' + no_such_domain, nslookup_stdout)

    def test04_resolve_ipv4_real_domain(self):
        for real_domain in self.real_domains:
            answers = self.test_ipv6_resolver.query(real_domain, A)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertNotEqual(self.result_addresses, self.fake_ipv4_addresses)
            self.assertNotEqual(len(self.result_addresses), 0)
            self.result_addresses.clear()

    def test05_resolve_ipv6_real_domain(self):
        for real_domain in self.real_domains:
            answers = self.test_ipv6_resolver.query(real_domain, AAAA)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertNotEqual(self.result_addresses, self.fake_ipv6_addresses)
            self.assertNotEqual(len(self.result_addresses), 0)
            self.result_addresses.clear()

    def test06_resolve_config_domains(self):
        for config_fake_domain in self.config_fake_domains:

            answers = self.test_ipv6_resolver.query(config_fake_domain, A)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertEqual(self.result_addresses, [self.fake_ipv4_addresses[0]])
            self.result_addresses.clear()

            answers = self.test_ipv6_resolver.query(config_fake_domain, AAAA)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertEqual(self.result_addresses, self.fake_ipv6_addresses)
            self.result_addresses.clear()

            answers = self.test_ipv6_resolver.query(config_fake_domain, NS)
            for answer in answers:
                self.result_addresses.append(str(answer.target)[:-1])
            self.assertEqual(self.result_addresses, [self.fake_ns_servers[0]])
            self.result_addresses.clear()

            answers = self.test_ipv6_resolver.query(config_fake_domain, MX)
            for answer in answers:
                self.result_addresses.append(str(answer.exchange)[:-1])
            self.assertEqual(self.result_addresses, self.fake_mx_servers)
            self.result_addresses.clear()

        for config_success_domain in self.config_success_domains:

            answers = self.test_ipv6_resolver.query(config_success_domain, A)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertEqual(self.result_addresses, [self.ipv4_address])
            self.result_addresses.clear()

            answers = self.test_ipv6_resolver.query(config_success_domain, AAAA)
            for answer in answers:
                self.result_addresses.append(answer.address)
            self.assertEqual(self.result_addresses, [self.ipv6_address])
            self.result_addresses.clear()

        for no_such_domain in self.config_no_such_domains:
            nslookup_process = run(['nslookup ' + no_such_domain + ' ' + self.ipv6_address], stdout=PIPE, shell=True)
            nslookup_stdout: str = nslookup_process.stdout.decode('utf-8')
            self.assertIn('server can\'t find ' + no_such_domain, nslookup_stdout)

        remove(self.config_file_name)

# endregion
