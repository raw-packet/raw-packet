# region Description
"""
setup.py: Raw-packet Project Setup
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from setuptools import setup, find_packages
# endregion

# region Authorship information
__author__ = 'Vladimir Ivanov'
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1.dev25'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion

# region Setup
with open("README.md", "r") as readme:
    long_description = readme.read()

setup(
    name="raw_packet",
    version=__version__,
    author=__author__,
    author_email=__email__,
    description="Raw-packet Project",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://raw-packet.github.io/",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Console :: Curses",
        "Environment :: MacOS X",
        "Intended Audience :: Education",
        "License :: Free For Educational Use",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Education",
        "Topic :: Security"
    ],
    install_requires=[
        "ipaddress",
        "netaddr",
        "scapy",
        "psutil",
        "prettytable",
        "distro",
        "xmltodict",
        "paramiko",
        "npyscreen",
        "pycryptodomex",
        "getmac",
        "colorama",
        "requests",
        "user-agents",
    ],
    extras_require={
        ':sys_platform=="darwin"': ['netifaces'],
        ':sys_platform=="linux"': ['netifaces']
    },
    entry_points={
        'console_scripts': [
            'apple_arp_dos=raw_packet.Scripts.Apple.apple_arp_dos:main',
            'apple_dhcp_server=raw_packet.Scripts.Apple.apple_dhcp_server:main',
            'apple_mitm=raw_packet.Scripts.Apple.apple_mitm:main',
            'arp_scan=raw_packet.Scripts.ARP.arp_scan:main',
            'arp_spoof=raw_packet.Scripts.ARP.arp_spoof:main',
            'dhcpv4_server=raw_packet.Scripts.DHCPv4.dhcpv4_server:main',
            'dhcpv6_server=raw_packet.Scripts.DHCPv6.dhcpv6_server:main',
            'dns_server=raw_packet.Scripts.DNS.dns_server:main',
            'icmpv4_redirect=raw_packet.Scripts.ICMPv4.icmpv4_redirect:main',
            'ipv6_scan=raw_packet.Scripts.IPv6.ipv6_scan:main',
            'ipv6_spoof=raw_packet.Scripts.IPv6.ipv6_spoof:main',
            'ncc=raw_packet.Scripts.NCC.ncc:main',
            'nsc=raw_packet.Scripts.NSC.nsc:main',
            'phishing=raw_packet.Scripts.Phishing.phishing:main',
            'wat=raw_packet.Scripts.WiFi.wat:main'
        ],
    },
    python_requires='>=3.6',
    include_package_data=True,
)
# endregion
