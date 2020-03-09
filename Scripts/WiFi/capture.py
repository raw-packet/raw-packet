#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
capture.py: Script for sniffing 802.11x authentication packets
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Add project root path
from sys import path
from os.path import dirname, abspath
from typing import Dict, Union
from textwrap import fill
from time import strftime
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


def print_function(request):
    try:
        iee80211_packet = request['802.11']

        if 'tag' in iee80211_packet.keys():
            if iee80211_packet['bss id'] not in bss_ids.keys():
                bss_ids[iee80211_packet['bss id']] = \
                    {'ssid': iee80211_packet['tag'][0].decode("utf-8"),
                     'channel': int.from_bytes(iee80211_packet['tag'][3], byteorder='little')}
                base.print_info('BSSID: ', iee80211_packet['bss id'],
                                ' ESSID: ', bss_ids[iee80211_packet['bss id']]['ssid'],
                                ' Channel: ', str(bss_ids[iee80211_packet['bss id']]['channel']))

        if '802.11x authentication' in iee80211_packet.keys():
            prefix: str = '    '

            # region First EAPOL message
            if iee80211_packet['802.11x authentication']['message number'] == 1 and \
                    iee80211_packet['bss id'] not in authentications.keys():
                bssid = iee80211_packet['bss id']
                authentications[bssid]: Dict[str, Union[int, str, bytes]] = dict()

                if bssid in bss_ids.keys():
                    authentications[bssid]['essid'] = bss_ids[bssid]['ssid']
                else:
                    authentications[bssid]['essid'] = 'Unknown'

                authentications[bssid]['key version'] = iee80211_packet['802.11x authentication']['version']
                authentications[bssid]['sta'] = iee80211_packet['destination']
                authentications[bssid]['anonce'] = iee80211_packet['802.11x authentication']['wpa key nonce']

                base.print_success('ESSID (length: ' + str(len(authentications[bssid]['essid'])) + '): ',
                                   authentications[bssid]['essid'])
                base.print_success('Key version: ', str(authentications[bssid]['key version']))
                base.print_success('BSSID: ', str(bssid))
                base.print_success('STA: ', str(authentications[bssid]['sta']))
                print_anonce: str = ' '.join('{:02X}'.format(x) for x in authentications[bssid]['anonce'])
                base.print_success('Anonce: \n', fill(print_anonce, width=52, initial_indent=prefix,
                                                      subsequent_indent=prefix))
            # endregion

            # region Second EAPOL message
            if iee80211_packet['802.11x authentication']['message number'] == 2 and \
                    iee80211_packet['bss id'] in authentications.keys():
                bssid = iee80211_packet['bss id']
                assert iee80211_packet['source'] == authentications[bssid]['sta'], 'Bad second EAPOL message'
                assert 'eapol' not in authentications[bssid].keys(), 'Authentication session already captured'

                authentications[bssid]['snonce'] = iee80211_packet['802.11x authentication']['wpa key nonce']
                authentications[bssid]['key mic'] = iee80211_packet['802.11x authentication']['wpa key mic']
                authentications[bssid]['eapol'] = iee80211_packet['802.11x authentication']['eapol']

                print_snonce: str = ' '.join('{:02X}'.format(x) for x in authentications[bssid]['snonce'])
                print_key_mic: str = ' '.join('{:02X}'.format(x) for x in authentications[bssid]['key mic'])
                print_eapol: str = ' '.join('{:02X}'.format(x) for x in authentications[bssid]['eapol'])

                base.print_success('Snonce: \n', fill(print_snonce, width=52, initial_indent=prefix,
                                                      subsequent_indent=prefix))
                base.print_success('Key MIC: \n', fill(print_key_mic, width=52, initial_indent=prefix,
                                                       subsequent_indent=prefix))
                base.print_success('EAPOL: \n', fill(print_eapol, width=52, initial_indent=prefix,
                                                     subsequent_indent=prefix))

                # region Save EAPOL session to hccapx file
                with open('/tmp/wpa' + str(authentications[bssid]['key version']) + '_' +
                          authentications[bssid]['essid'] + '_' +
                          strftime('%Y%m%d_%H%M%S') + '.hccapx', 'wb') as hccapx_file:
                    hccapx_file.write(b'HCPX\x04\x00\x00\x00\x02\x0a')  # write Descriptor
                    hccapx_file.write(authentications[bssid]['essid'].encode('utf-8'))  # write ESSID
                    # reserved 32 bytes for ESSID
                    hccapx_file.write(b''.join(b'\x00' for _ in range(32 - len(authentications[bssid]['essid']))))
                    hccapx_file.write(b'\x02')
                    hccapx_file.write(authentications[bssid]['key mic'])  # write wpa key mic
                    hccapx_file.write(eth.convert_mac(bssid))  # write BSSID
                    hccapx_file.write(authentications[bssid]['anonce'])  # write AP wpa key nonce
                    hccapx_file.write(eth.convert_mac(authentications[bssid]['sta']))  # write STA
                    hccapx_file.write(authentications[bssid]['snonce'])  # write STA wpa key nonce
                    hccapx_file.write(b'\x79\x00')
                    hccapx_file.write(authentications[bssid]['eapol'])  # write STA EAPOL key data
                    # reserved 256 bytes for STA EAPOL key data
                    hccapx_file.write(b''.join(b'\x00' for _ in range(256 - len(authentications[bssid]['eapol']))))
                # endregion

            # endregion

    except AssertionError:
        pass


# region Main function
if __name__ == "__main__":

    path.append(dirname(dirname(dirname(abspath(__file__)))))

    from raw_packet.Utils.base import Base
    from raw_packet.Utils.network import RawSniff
    from raw_packet.Utils.network import RawEthernet

    base: Base = Base()
    sniff: RawSniff = RawSniff()
    eth: RawEthernet = RawEthernet()

    bss_ids: Dict[str, Dict[str, str]] = dict()
    authentications: Dict[str, Dict[str, Union[int, str, bytes]]] = dict()

    # region Start sniffer
    try:
        sniff.start(protocols=['Radiotap', '802.11'], prn=print_function,
                    network_interface='wlan0', filters={'802.11': {'types': [0x80, 0x88]}})
    except KeyboardInterrupt:
        base.print_info('Exit ...')
    # endregion

# endregion
