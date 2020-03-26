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
from typing import Dict, Union
from collections import OrderedDict
from time import sleep
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

    wifi_channel: int = -1

    def create(self):
        y, x = self.useable_space()
        self.grid = self.add(MainGrid, col_titles=titles, column_width=21, max_height=3*y//4)
        self.grid.add_handlers({
            ascii.CR: self.ap_info,
            ascii.NL: self.ap_info,
            "^I": self.ap_info,
            "^D": self.deauth,
            "^S": self.switch_wifi_channel,
            "^A": self.association
        })
        self.InfoBox = self.add(InfoBox, editable=False, name='Information')

    def while_waiting(self):
        self.grid.values = self.get_wifi_ssid_rows()
        self.InfoBox.value = self.get_info_messages()
        self.InfoBox.display()

    def switch_wifi_channel(self, args):
        popup = npyscreen.Popup(name="Set WiFi channel")
        channels = popup.add(npyscreen.TitleSelectOne, name='Channel', scroll_exit=True,
                             values=[1, 2, 3, 5, 6, 7, 8, 9, 10, 11])
        popup.edit()
        if len(channels.get_selected_objects()) > 0:
            current_wifi_channel: int = channels.get_selected_objects()[0]
            self.wifi_channel = current_wifi_channel
            thread_manager.add_task(wifi.set_wifi_channel, current_wifi_channel)

    def deauth(self, args):
        try:
            bssid = self.grid.selected_row()[1]
            assert bssid in wifi.bssids.keys(), 'Could not find AP with BSSID: ' + bssid
            if len(wifi.bssids[bssid]['clients']) > 0:
                popup = npyscreen.Popup(name="Choose client for deauth")
                deauth_clients = popup.add(npyscreen.TitleMultiSelect, name='Deauth', scroll_exit=True,
                                           values=wifi.bssids[bssid]['clients'])
                popup.edit()
                if len(deauth_clients.get_selected_objects()) > 0:
                    for client in deauth_clients.get_selected_objects():
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

    def association(self, args):
        try:
            bssid = self.grid.selected_row()[1]
            assert bssid in wifi.bssids.keys(), 'Could not find AP with BSSID: ' + bssid
            thread_manager.add_task(wifi.send_association_request, bssid, wifi.bssids[bssid]['essid'])

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
            # endregion

            # region RSN PMKID
            if len(wifi.pmkid_authentications) > 0:
                for bssid in wifi.pmkid_authentications.keys():
                    if 'file' in wifi.pmkid_authentications[bssid].keys():
                        results[wifi.pmkid_authentications[bssid]['timestamp']] = \
                            '[+] Sniff WPA' + str(wifi.pmkid_authentications[bssid]['key version']) + \
                            ' RSN PMKID for ESSID: ' + wifi.pmkid_authentications[bssid]['essid'] + \
                            ' BSSID: ' + bssid + \
                            ' Client: ' + wifi.pmkid_authentications[bssid]['client'] + '\n'
            # endregion

            # region Deauth Packets
            if len(wifi.deauth_packets) > 0:
                for deauth_dictioanry in wifi.deauth_packets:
                    results[deauth_dictioanry['timestamp']] = \
                        '[*] Send ' + str(deauth_dictioanry['packets']) + \
                        ' deauth packets BSSID: ' + str(deauth_dictioanry['bssid']) + \
                        ' Client: ' + str(deauth_dictioanry['client']) + '\n'
            # endregion

            # region Association Packets
            if len(wifi.association_packets) > 0:
                for association_dictioanry in wifi.association_packets:
                    results[association_dictioanry['timestamp']] = \
                        '[*] Send association request packets' \
                        ' ESSID: ' + association_dictioanry['essid'] + \
                        ' BSSID: ' + str(association_dictioanry['bssid']) + \
                        ' Client: ' + str(association_dictioanry['client']) + '\n'
            # endregion

            # region WiFi channels
            if len(wifi.channels) > 0:
                for channel_dictionary in wifi.channels:
                    results[channel_dictionary['timestamp']] = \
                        '[*] Set WiFi channel: ' + str(channel_dictionary['channel']) + '\n'
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

    def get_wifi_ssid_rows(self) -> List[List[str]]:
        rows: List[List[str]] = list()
        results: List[Dict[str, Union[int, str]]] = list()
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
                if self.wifi_channel != -1:
                    assert wifi.bssids[bssid]['channel'] == self.wifi_channel, 'Bad WiFi channel'

                results.append({
                    'essid': wifi.bssids[bssid]['essid'],
                    'bssid': bssid,
                    'signal': wifi.bssids[bssid]['signal'],
                    'channel': wifi.bssids[bssid]['channel'],
                    'encryption': wifi.bssids[bssid]['enc'] + ' ' +
                                  wifi.bssids[bssid]['auth'] + ' ' +
                                  wifi.bssids[bssid]['cipher'],
                    'clients': len(wifi.bssids[bssid]['clients'])})

            except AssertionError:
                pass

        sorted_results: List[Dict[str, Union[int, str]]] = sorted(results, key=lambda k: k['signal'], reverse=True)
        for sorted_result in sorted_results:
            rows.append([sorted_result['essid'],
                         sorted_result['bssid'],
                         sorted_result['signal'],
                         sorted_result['channel'],
                         sorted_result['encryption'],
                         sorted_result['clients']])

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
    parser.add_argument('-b', '--bssid', help='Set AP BSSID', default=None)
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
        if args.channel is None and args.bssid is None:
            wifi: WiFi = WiFi(wireless_interface=wireless_interface)
        elif args.channel is not None and args.bssid is None:
            wifi: WiFi = WiFi(wireless_interface=wireless_interface, wifi_channel=args.channel)
        elif args.channel is None and args.bssid is not None:
            assert False, 'Please set WiFi channel for BSSID: ' + base.info_text(args.bssid)
        else:
            wifi: WiFi = WiFi(wireless_interface=wireless_interface, wifi_channel=args.channel, ap_bssid=args.bssid)
        # endregion

        # region Start WiFi Sniffer
        wifi_sniffer: WiFiSniffer = WiFiSniffer()
        wifi_sniffer.run()
        # endregion

    except KeyboardInterrupt:
        base.print_info('Exit ....')

    except AssertionError as Error:
        base.print_error(Error.args[0])
        exit(1)

# endregion
