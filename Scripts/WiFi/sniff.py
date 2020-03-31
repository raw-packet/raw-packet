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
from typing import Dict, Union
from collections import OrderedDict
from time import sleep
import npyscreen
import curses
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
        npyscreen.setTheme(npyscreen.Themes.DefaultTheme)
        self.addForm("MAIN", MainForm, name='WiFi SSID\'s', color='DEFAULT')

    def process_event_queues(self, max_events_per_queue=None):
        try:
            for queue in self.event_queues.values():
                for event in queue.get(maximum=max_events_per_queue):
                    self.process_event(event)
        except RuntimeError:
            pass
# endregion


# region Change method make_contained_widgets in npyscreen class SimpleGrid
class SimpleGrid(npyscreen.SimpleGrid):

    # Add custom widths for columns
    def make_contained_widgets(self):
        if self.column_width_requested:
            # don't need a margin for the final column
            self.columns = (self.width + self.col_margin) // (self.column_width_requested + self.col_margin)
        elif self.columns_requested:
            self.columns = self.columns_requested
        else:
            self.columns = self.default_column_number
        self._my_widgets = []
        column_width = (self.width + self.col_margin - self.additional_x_offset) // self.columns
        column_width -= self.col_margin
        self._column_width = column_width
        if column_width < 1: raise Exception("Too many columns for space available")
        for h in range((self.height - self.additional_y_offset) // self.row_height):
            h_coord = h * self.row_height
            row = []
            x_offset = 0
            if len(self.column_widths) > 0:
                for cell in range(self.columns):
                    if cell > 0:
                        x_offset += self.column_widths[cell - 1] + self.col_margin
                    if cell >= len(self.column_widths):
                        self.column_widths.append(self._column_width)
                    row.append(self._contained_widgets(self.parent, rely=h_coord + self.rely + self.additional_y_offset,
                                                       relx=self.relx + x_offset + self.additional_x_offset,
                                                       width=self.column_widths[cell], height=self.row_height))
            else:
                for cell in range(self.columns):
                        x_offset = cell * (self._column_width + self.col_margin)
                        row.append(self._contained_widgets(self.parent, rely=h_coord + self.rely + self.additional_y_offset,
                                                           relx=self.relx + x_offset + self.additional_x_offset,
                                                           width=column_width, height=self.row_height))
            self._my_widgets.append(row)
# endregion


# region Grid for Main Form
class GridColTitles(SimpleGrid):
    additional_y_offset = 2
    _col_widgets = npyscreen.Textfield

    def __init__(self, screen, col_titles: List[str] = None, col_widths: List[int] = None, *args, **keywords):
        if col_titles:
            self.col_titles = col_titles
        else:
            self.col_titles = []
        if col_widths:
            self.column_widths = col_widths
        else:
            self.column_widths = []
        super(GridColTitles, self).__init__(screen, *args, **keywords)

    def make_contained_widgets(self):
        super(GridColTitles, self).make_contained_widgets()
        self._my_col_titles = []

        if len(self.column_widths) > 0:
            x_offset = 0
            for title_cell in range(self.columns):
                if title_cell > 0:
                    x_offset += self.column_widths[title_cell - 1] + self.col_margin
                if title_cell >= len(self.column_widths):
                    self.column_widths.append(self._column_width)
                self._my_col_titles.append(self._col_widgets(self.parent, rely=self.rely, relx=self.relx + x_offset,
                                                             width=self.column_widths[title_cell], height=1))
        else:
            for title_cell in range(self.columns):
                x_offset = title_cell * (self._column_width+self.col_margin)
                self._my_col_titles.append(self._col_widgets(self.parent, rely=self.rely, relx=self.relx + x_offset,
                                                             width=self._column_width, height=1))

    def update(self, clear=True):
        super(GridColTitles, self).update(clear=True)

        _title_counter = 0
        for title_cell in self._my_col_titles:
            try:
                title_text = self.col_titles[self.begin_col_display_at + _title_counter]
            except IndexError:
                title_text = None
            self.update_title_cell(title_cell, title_text)
            _title_counter += 1

        self.parent.curses_pad.hline(self.rely + 1, self.relx, curses.ACS_HLINE, self.width)

    def update_title_cell(self, cell, cell_title):
        cell.value = cell_title
        cell.update()
# endregion


# region Set colors for information output strings
class MultiLineColor(npyscreen.MultiLine):

    def _print_line(self, line, value_indexer):
        super()._print_line(line, value_indexer)
        try:
            if line.value.startswith('[+]'):
                line.color = 'GOOD'
                line.show_bold = True
            if line.value.startswith('[*]'):
                line.color = 'STANDOUT'
        except AttributeError:
            pass
# endregion


# region Box for information messages
class InfoBox(npyscreen.BoxTitle):
    _contained_widget = MultiLineColor
# endregion


# region Main Form
class MainForm(npyscreen.FormBaseNew):

    # region Variables
    titles: List[str] = ['ESSID', 'BSSID', 'Signal', 'Channel', 'Encryption', 'Clients']
    wifi_channel: int = -1
    x: int = 0
    y: int = 0
    deauth_popup_name: str = 'Choose client for deauth'
    deauth_multi_select_name: str = 'Deauth'
    channel_popup_name: str = 'Set WiFi channel'
    channel_one_select_name: str = 'Channel'
    # endregion

    def create(self):
        self.y, self.x = self.useable_space()
        self.grid = self.add(GridColTitles, col_titles=self.titles,
                             column_width=15, col_widths=[25, 18, 10, 10, 23, 10],
                             max_height=2 * self.y // 3, select_whole_line=True)
        self.grid.add_handlers({
            curses.ascii.CR: self.ap_info,
            curses.ascii.NL: self.ap_info,
            "^I": self.ap_info,
            "^D": self.deauth,
            "^S": self.switch_wifi_channel,
            "^A": self.association,
            "^R": self.resume_scanner
        })
        self.InfoBox = self.add(InfoBox, name='Information')

    def while_waiting(self):
        self.grid.values = self.get_wifi_ssid_rows()
        self.InfoBox.values = self.get_info_messages()
        self.InfoBox.display()

    def resume_scanner(self, args):
        self.wifi_channel = -1
        wifi.resume_scan_ssids()

    def switch_wifi_channel(self, args):
        popup_columns: int = len(self.channel_one_select_name) + 25
        popup_lines: int = len(wifi.available_wifi_channels) + 4
        if popup_lines > int(3 * self.y // 4):
            popup_lines = int(3 * self.y // 4)

        popup = npyscreen.Popup(name=self.channel_popup_name,
                                columns=popup_columns,
                                lines=popup_lines)
        channels = popup.add(npyscreen.TitleSelectOne, name=self.channel_one_select_name, scroll_exit=True,
                             values=wifi.available_wifi_channels)
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
                clients_list: List[str] = self.make_client_list(wifi.bssids[bssid]['clients'])

                popup_columns: int = len(max(clients_list, key=len)) + len(self.deauth_multi_select_name) + 22
                popup_lines: int = len(clients_list) + 4

                if popup_columns > int(3 * self.x // 4):
                    popup_columns = int(3 * self.x // 4)
                if popup_lines > int(3 * self.y // 4):
                    popup_lines = int(3 * self.y // 4)
                if popup_lines < 6:
                    popup_lines = 6

                popup = npyscreen.Popup(name=self.deauth_popup_name,
                                        columns=popup_columns,
                                        lines=popup_lines)
                deauth_clients = popup.add(npyscreen.TitleMultiSelect, name=self.deauth_multi_select_name,
                                           scroll_exit=True, values=clients_list)
                popup.edit()
                if len(deauth_clients.get_selected_objects()) > 0:
                    if self.wifi_channel != wifi.bssids[bssid]['channel']:
                        self.wifi_channel = wifi.bssids[bssid]['channel']
                        wifi.set_wifi_channel(channel=wifi.bssids[bssid]['channel'])
                    for client in deauth_clients.get_selected_objects():
                        thread_manager.add_task(wifi.send_deauth, bssid, client[0:17], 50)
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
            thread_manager.add_task(wifi.send_association_request, bssid, wifi.bssids[bssid]['essid'], True)

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

    def get_ap_info(self, bssid: str = '12:34:56:78:90:ab') -> str:
        try:
            assert bssid in wifi.bssids.keys(), 'Could not find AP with BSSID: ' + bssid
            clients_list: List[str] = self.make_client_list(wifi.bssids[bssid]['clients'])
            ap_info: str = ''
            ap_info += '[*] ESSID: ' + str(wifi.bssids[bssid]['essid']) + '\n'
            ap_info += '[*] BSSID: ' + str(bssid) + '\n'

            # region Information about WPA handshakes
            handshake_clients_address: List[str] = list()
            if bssid in wifi.wpa_handshakes.keys():
                for client in wifi.wpa_handshakes[bssid].keys():
                    if 'hashcat 22000 file' in wifi.wpa_handshakes[bssid][client].keys():
                        handshake_clients_address.append(client)
            if len(handshake_clients_address) > 0:
                handshake_clients_address_and_vendor: List[str] = self.make_client_list(handshake_clients_address)
                ap_info += '[+] Sniff WPA handshake from STATIONS: \n'
                for client in handshake_clients_address_and_vendor:
                    ap_info += '    ' + client + '\n'
            # endregion

            # region Information about WPA handshakes
            if bssid in wifi.pmkid_authentications.keys():
                if 'file' in wifi.pmkid_authentications[bssid].keys():
                    ap_info += '[+] Sniff WPA' + str(wifi.pmkid_authentications[bssid]['key version']) + \
                               ' RSN PMKID\n'
            # endregion

            ap_info += '[*] Signal: ' + str(wifi.bssids[bssid]['signal']) + '\n'
            ap_info += '[*] Encryption: ' + str(wifi.bssids[bssid]['enc']) + '\n'
            ap_info += '[*] Cipher: ' + str(wifi.bssids[bssid]['cipher']) + '\n'
            ap_info += '[*] Authentication: ' + str(wifi.bssids[bssid]['auth']) + '\n'
            if len(clients_list) > 0:
                ap_info += '[*] Clients:\n'
                for client in clients_list:
                    ap_info += '    ' + client + '\n'
            return ap_info

        except AssertionError as Error:
            return Error.args[0]

    @staticmethod
    def make_client_list(clients: List[str]) -> List[str]:
        clients_list: List[str] = list()
        for client_mac_address in clients:
            vendor_list: List[str] = base.get_vendor_by_mac_address(client_mac_address).split()
            vendor: str = vendor_list[0]
            if len(vendor_list) >= 2:
                vendor += ' ' + vendor_list[1].replace(',', '')
            clients_list.append(client_mac_address + ' (' + vendor + ')')
        return clients_list

    @staticmethod
    def get_info_messages() -> List[str]:
        results_list: List[str] = list()
        results_dict: Dict[float, str] = dict()

        try:

            # region WPA Handshakes
            if len(wifi.wpa_handshakes) > 0:
                for bssid in wifi.wpa_handshakes.keys():
                    for client in wifi.wpa_handshakes[bssid].keys():
                        if isinstance(wifi.wpa_handshakes[bssid][client], dict):
                            if 'hashcat 22000 file' in wifi.wpa_handshakes[bssid][client].keys():
                                results_dict[wifi.wpa_handshakes[bssid][client]['timestamp']] = \
                                    '[+] Sniff WPA' + str(wifi.wpa_handshakes[bssid][client]['key version']) + \
                                    ' handshake for STATION: ' + client + ' BSSID: ' + bssid + \
                                    ' ESSID: ' + wifi.wpa_handshakes[bssid][client]['essid']
            # endregion

            # region RSN PMKID
            if len(wifi.pmkid_authentications) > 0:
                for bssid in wifi.pmkid_authentications.keys():
                    if 'file' in wifi.pmkid_authentications[bssid].keys():
                        results_dict[wifi.pmkid_authentications[bssid]['timestamp']] = \
                            '[+] Sniff WPA' + str(wifi.pmkid_authentications[bssid]['key version']) + \
                            ' RSN PMKID for STATION: ' + wifi.pmkid_authentications[bssid]['client'] + \
                            ' BSSID: ' + bssid + \
                            ' ESSID: ' + wifi.pmkid_authentications[bssid]['essid']
            # endregion

            # region Deauth Packets
            if len(wifi.deauth_packets) > 0:
                for deauth_dictioanry in wifi.deauth_packets:
                    results_dict[deauth_dictioanry['timestamp']] = \
                        '[*] Send ' + str(deauth_dictioanry['packets']) + \
                        ' deauth packets for STATION: ' + str(deauth_dictioanry['client']) + \
                        ' BSSID: ' + str(deauth_dictioanry['bssid'])
            # endregion

            # region Association Packets
            if len(wifi.association_packets) > 0:
                for association_dictioanry in wifi.association_packets:
                    if association_dictioanry['verbose']:
                        results_dict[association_dictioanry['timestamp']] = \
                            '[*] Send association request packets' \
                            ' STATION: ' + str(association_dictioanry['client']) + \
                            ' BSSID: ' + str(association_dictioanry['bssid']) + \
                            ' ESSID: ' + association_dictioanry['essid']
            # endregion

            # region WiFi channels
            if len(wifi.channels) > 0:
                channel_dictionary: Dict[str, Union[int, float]] = wifi.channels[len(wifi.channels) - 1]
                results_dict[channel_dictionary['timestamp']] = \
                    '[*] Current WiFi channel: ' + str(channel_dictionary['channel'])
            # endregion

            # region Kr00k Packets
            if len(wifi.kr00k_packets) > 0:
                for source in wifi.kr00k_packets:
                    for destination in wifi.kr00k_packets[source]:
                        if wifi.kr00k_packets[source][destination]['direction'] == 'to-AP':
                            results_dict[wifi.kr00k_packets[source][destination]['timestamp']] = \
                                '[+] Sniff ' + str(wifi.kr00k_packets[source][destination]['count']) + \
                                ' kr00k packets from STATION: ' + str(source) + \
                                ' -> to BSSID: ' + str(destination)
                        if wifi.kr00k_packets[source][destination]['direction'] == 'from-AP':
                            results_dict[wifi.kr00k_packets[source][destination]['timestamp']] = \
                                '[+] Sniff ' + str(wifi.kr00k_packets[source][destination]['count']) + \
                                ' kr00k packets to STATION: ' + str(source) + \
                                ' <- from BSSID: ' + str(destination)
            # endregion

            # region Return result string sorted by Timestamp
            ordered_results = OrderedDict(reversed(sorted(results_dict.items())))
            for timestamp, info_message in ordered_results.items():
                results_list.append(info_message)
            return results_list
            # endregion

        except AssertionError:
            return results_list

        except KeyError:
            return results_list

        except IndexError:
            return results_list

        except AttributeError:
            return results_list

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
            if 'WPA' in sorted_result['encryption'] and \
                    sorted_result['bssid'] not in wifi.pmkid_authentications.keys():
                thread_manager.add_task(wifi.send_association_request,
                                        sorted_result['bssid'],
                                        sorted_result['essid'],
                                        False)
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
            wifi: WiFi = WiFi(wireless_interface=wireless_interface)
        else:
            wifi: WiFi = WiFi(wireless_interface=wireless_interface, wifi_channel=args.channel)
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
