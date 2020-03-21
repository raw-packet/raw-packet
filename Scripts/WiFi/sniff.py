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

# region Import
from sys import path
from os.path import dirname, abspath
from typing import List
from argparse import ArgumentParser
from curses import ascii
from typing import Dict
from collections import OrderedDict
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


# region WiFiSniffer Application
class WiFiSniffer(npyscreen.StandardApp):
    def onStart(self):
        self.addForm("MAIN", MainForm, name='WiFi SSID\'s', color='DEFAULT')

    def process_event_queues(self, max_events_per_queue=None):
        try:
            for queue in self.event_queues.values():
                for event in queue.get(maximum=max_events_per_queue):
                    self.process_event(event)
        except RuntimeError:
            pass
# endregion


# region Grid for Main Form
class MainGrid(npyscreen.GridColTitles):
    def test(self):
        pass
# endregion


# region Box for information messages
class InfoBox(npyscreen.BoxTitle):
    _contained_widget = npyscreen.MultiLineEdit
# endregion


# region Main Form
class MainForm(npyscreen.Form):

    def create(self):
        y, x = self.useable_space()
        self.grid = self.add(MainGrid, col_titles=titles, column_width=20, max_height=3*y//4)
        self.grid.add_handlers({
            ascii.CR: self.ap_info,
            ascii.NL: self.ap_info,
            "^I": self.ap_info,
            "^D": self.deauth
        })
        self.InfoBox = self.add(InfoBox, editable=False, name='Information')

    def while_waiting(self):
        self.grid.values = self.get_wifi_ssid_rows()
        self.InfoBox.value = self.get_info_messages()
        self.InfoBox.display()

    def deauth(self, args):
        try:
            bssid = self.grid.selected_row()[1]
            assert bssid in wifi.bssids.keys(), 'Could not find AP with BSSID: ' + bssid
            if len(wifi.bssids[bssid]['clients']) > 0:
                popup = npyscreen.Popup(name="Choose client for deauth")
                opt = popup.add(npyscreen.TitleMultiSelect, name='Deauth', scroll_exit=True,
                                values=wifi.bssids[bssid]['clients'])
                popup.edit()
                if len(opt.get_selected_objects()) > 0:
                    for client in opt.get_selected_objects():
                        thread_manager.add_task(wifi.send_deauth, bssid, client, 50)
            else:
                npyscreen.notify_confirm('Not found clients for AP: ' + wifi.bssids[bssid]['essid'] +
                                         ' (' + bssid + ')', title="Deauth Error")
                self.parentApp.switchFormPrevious()

        except AssertionError as Error:
            npyscreen.notify_confirm(Error.args[0], title="Assertion Error")
            self.parentApp.switchFormPrevious()

        except IndexError:
            pass

        except TypeError:
            pass

    def ap_info(self, args):
        try:
            npyscreen.notify_confirm(self.get_ap_info(self.grid.selected_row()[1]), title="AP information")
            self.parentApp.switchFormPrevious()
        except IndexError:
            pass

    @staticmethod
    def get_ap_info(bssid: str = '12:34:56:78:90:ab') -> str:
        try:
            assert bssid in wifi.bssids.keys(), 'Could not find AP with BSSID: ' + bssid
            ap_info: str = ''
            ap_info += 'ESSID: ' + str(wifi.bssids[bssid]['essid']) + '\n'
            ap_info += 'BSSID: ' + str(bssid) + '\n'
            ap_info += 'Signal: ' + str(wifi.bssids[bssid]['signal']) + '\n'
            ap_info += 'Encryption: ' + str(wifi.bssids[bssid]['enc']) + '\n'
            ap_info += 'Cipher: ' + str(wifi.bssids[bssid]['cipher']) + '\n'
            ap_info += 'Authentication: ' + str(wifi.bssids[bssid]['auth']) + '\n'
            ap_info += 'Clients: ' + str(wifi.bssids[bssid]['clients']) + '\n'
            return ap_info

        except AssertionError as Error:
            return Error.args[0]

    @staticmethod
    def get_info_messages() -> str:
        result: str = ''
        results: Dict[float, str] = dict()

        try:

            # region WPA Handshakes
            if len(wifi.wpa_handshakes) > 0:
                for bssid in wifi.wpa_handshakes.keys():
                    for client in wifi.wpa_handshakes[bssid].keys():
                        if isinstance(wifi.wpa_handshakes[bssid][client], dict):
                            if 'hashcat 22000 file' in wifi.wpa_handshakes[bssid][client].keys():
                                results[wifi.wpa_handshakes[bssid][client]['timestamp']] = \
                                    '[+] Sniff WPA' + str(wifi.wpa_handshakes[bssid][client]['key version']) + \
                                    ' handshake for ESSID: ' + wifi.wpa_handshakes[bssid][client]['essid'] + \
                                    ' BSSID: ' + bssid + ' Client: ' + client + '\n'
                                # result += '[+] Handshake in PCAP format save to file: ' + \
                                #           wifi.wpa_handshakes[bssid][client]['pcap file'] + '\n'
                                # result += '[+] Handshake in HCCAPX format save to file: ' + \
                                #           wifi.wpa_handshakes[bssid][client]['hccapx file'] + '\n'
                                # result += '[+] Handshake in Hashcat 22000 format save to file: ' + \
                                #           wifi.wpa_handshakes[bssid][client]['hashcat 22000 file'] + '\n'
            # endregion

            # region Deauth Packets
            if len(wifi.deauth_packets) > 0:
                for deauth_dictioanry in wifi.deauth_packets:
                    results[deauth_dictioanry['timestamp']] = \
                        '[*] Send ' + str(deauth_dictioanry['packets']) + \
                        ' deauth packets BSSID: ' + str(deauth_dictioanry['bssid']) + \
                        ' Client: ' + str(deauth_dictioanry['client']) + '\n'
            # endregion

            # region Return result string sorted by Timestamp
            ordered_results = OrderedDict(reversed(sorted(results.items())))
            for timestamp, info_message in ordered_results.items():
                result += info_message
            return result
            # endregion

        except AssertionError:
            return result

        except KeyError:
            return result

        except IndexError:
            return result

        except AttributeError:
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

                assert wifi.bssids[bssid]['enc'] != 'UNKNOWN', 'Bad Encryption'
                assert wifi.bssids[bssid]['cipher'] != 'UNKNOWN', 'Bad Cipher'
                assert wifi.bssids[bssid]['auth'] != 'UNKNOWN', 'Bad Authentication'

                rows.append([wifi.bssids[bssid]['essid'], bssid,
                             wifi.bssids[bssid]['signal'],
                             wifi.bssids[bssid]['channel'],
                             wifi.bssids[bssid]['enc'] + ' ' +
                             wifi.bssids[bssid]['auth'] + ' ' +
                             wifi.bssids[bssid]['cipher'],
                             len(wifi.bssids[bssid]['clients'])])

            except AssertionError:
                pass
        return rows
# endregion


# region Main function
if __name__ == "__main__":

    # region Import Raw-packet modules
    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.base import Base
    from raw_packet.Utils.wifi import WiFi
    from raw_packet.Utils.tm import ThreadManager
    base: Base = Base()
    thread_manager: ThreadManager = ThreadManager(10)
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
