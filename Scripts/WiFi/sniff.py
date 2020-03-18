#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# region Description
"""
sniff.py: Script for sniffing 802.11x authentication packets
Author: Vladimir Ivanov
License: MIT
Copyright 2020, Raw-packet Project
"""
# endregion

# region Add project root path
from sys import path
from os.path import dirname, abspath
from typing import List
from argparse import ArgumentParser
import npyscreen
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


class WiFiSniffer(npyscreen.StandardApp):
    def onStart(self):
        self.addForm("MAIN", MainForm, name="WiFi SSID's", color='DEFAULT')

    def process_event_queues(self, max_events_per_queue=None):
        try:
            for queue in self.event_queues.values():
                for event in queue.get(maximum=max_events_per_queue):
                    self.process_event(event)
        except RuntimeError:
            pass


class MyGrid(npyscreen.GridColTitles):
    def test(self):
        pass

    # def custom_print_cell(self, actual_cell, cell_display_value):
    #     if cell_display_value == 'FAIL':
    #        actual_cell.color = 'DANGER'
    #     elif cell_display_value == 'PASS':
    #        actual_cell.color = 'GOOD'
    #     else:
    #        actual_cell.color = 'DEFAULT'


class InfoBox(npyscreen.BoxTitle):
    _contained_widget = npyscreen.MultiLineEdit


class MainForm(npyscreen.FormBaseNew):

    def create(self):
        y, x = self.useable_space()
        self.gd = self.add(MyGrid, col_titles=titles, column_width=20, max_height=y//2)
        self.InfoBox = self.add(InfoBox, editable=False, name='Information')
        self.gd.values = []

    def while_waiting(self):
        self.gd.values = self.get_wifi_ssid_rows()
        self.InfoBox.value = self.pop_info_messages()
        self.InfoBox.display()

    @staticmethod
    def pop_info_messages() -> str:
        result: str = ''
        try:
            assert len(wifi.wpa_handshakes) > 0, 'Not Found WPA handhakes'
            for bssid in wifi.wpa_handshakes.keys():
                assert 'hashcat 22000 content' in wifi.wpa_handshakes[bssid].keys(), 'Not full WPA handhake'
                # result = wifi.wpa_handshakes[bssid]['hashcat 22000 content'] + '\n'
                result += '[+] Sniff WPA' + str(wifi.wpa_handshakes[bssid]['key version']) + \
                          ' handshake for ESSID: ' + wifi.wpa_handshakes[bssid]['essid'] + \
                          ' BSSID: ' + bssid + ' Client: ' + wifi.wpa_handshakes[bssid]['sta'] + '\n'
                result += '[+] Handshake in PCAP format save to file: ' + \
                          wifi.wpa_handshakes[bssid]['pcap file'] + '\n'
                result += '[+] Handshake in HCCAPX format save to file: ' + \
                          wifi.wpa_handshakes[bssid]['hccapx file'] + '\n'
                result += '[+] Handshake in Hashcat 22000 format save to file: ' + \
                          wifi.wpa_handshakes[bssid]['hashcat 22000 file'] + '\n'
            return result
        except AssertionError:
            return result

    @staticmethod
    def get_wifi_ssid_rows() -> List[List[str]]:
        rows: List[List[str]] = list()
        for bssid in wifi.bssids.keys():
            try:
                assert 'essid' in wifi.bssids[bssid].keys() and \
                       'signal' in wifi.bssids[bssid].keys() and \
                       'channel' in wifi.bssids[bssid].keys() and \
                       'enc' in wifi.bssids[bssid].keys() and \
                       'cipher' in wifi.bssids[bssid].keys() and \
                       'auth' in wifi.bssids[bssid].keys() and \
                       'clients' in wifi.bssids[bssid].keys(), 'Bad AP'

                assert wifi.bssids[bssid]['enc'] != 'UNKNOWN' or \
                       wifi.bssids[bssid]['cipher'] != 'UNKNOWN' or \
                       wifi.bssids[bssid]['auth'] != 'UNKNOWN', 'Bad Encryption'

                rows.append([
                    wifi.bssids[bssid]['essid'],
                    bssid,
                    wifi.bssids[bssid]['signal'],
                    wifi.bssids[bssid]['channel'],
                    wifi.bssids[bssid]['enc'] + ' ' + wifi.bssids[bssid]['auth'] + ' ' + wifi.bssids[bssid]['cipher'],
                    len(wifi.bssids[bssid]['clients'])])

            except AssertionError:
                pass
        return rows


# region Main function
if __name__ == "__main__":

    # region Import Raw-packet modules
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.base import Base
    from raw_packet.Utils.wifi import WiFi
    base: Base = Base()
    # endregion

    # region Variables
    titles = ['ESSID', 'BSSID', 'Signal', 'Channel', 'Encryption', 'Clients']
    # endregion

    # region Check user and platform
    base.check_user()
    # endregion

    # region Parse script arguments
    parser: ArgumentParser = ArgumentParser(description='Sniffing 802.11x authentication packets')
    parser.add_argument('-i', '--interface', help='Set wireless interface name for sniff packets', default=None)
    parser.add_argument('-c', '--channel', type=int, help='Set WiFi channel', default=None)
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')
    args = parser.parse_args()
    # endregion

    # region Print banner
    if not args.quiet:
        base.print_banner()
    # endregion

    try:
        # region Get wireless network interface
        if args.interface is None:
            base.print_warning('Please set a wireless network interface ...')
        wireless_interface: str = base.network_interface_selection(interface_name=args.interface, only_wireless=True)
        # endregion

        # region Init Raw-packet WiFi class
        if args.channel is None:
            wifi: WiFi = WiFi(wireless_interface)
        else:
            wifi: WiFi = WiFi(wireless_interface, args.channel)
        # endregion

        wifi_sniffer: WiFiSniffer = WiFiSniffer()
        wifi_sniffer.run()

    except KeyboardInterrupt:
        base.print_info('Exit ....')

# endregion
