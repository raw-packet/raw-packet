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
import npyscreen
import curses
from time import sleep
from typing import Dict, Union, List
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


class WiFiAttackTool(npyscreen.StandardApp):
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
    def custom_print_cell(self, actual_cell, cell_display_value):
        if 'Off' in cell_display_value or '<error>' in cell_display_value or 'iOS10' in cell_display_value or 'iOS11' in cell_display_value or 'Disabled' in cell_display_value:
            actual_cell.color = 'DANGER'
        elif 'Lock screen' in cell_display_value or 'iOS12' in cell_display_value:
            actual_cell.color = 'CONTROL'
        else:
            actual_cell.color = 'DEFAULT'


class OutputBox(npyscreen.BoxTitle):
    _contained_widget = npyscreen.MultiLineEdit


class VerbOutputBox(npyscreen.BoxTitle):
    _contained_widget = npyscreen.MultiLineEdit


class MainForm(npyscreen.FormBaseNew):

    def create(self):
        new_handlers = {
            "^Q": self.exit_func
        }
        self.add_handlers(new_handlers)
        y, x = self.useable_space()
        self.gd = self.add(MyGrid, col_titles=titles, column_width=18)
        self.gd.values = []
        # self.gd.add_handlers({curses.ascii.NL: self.upd_cell})

    def while_waiting(self):
        self.gd.values = self.get_wifi_ssid_rows()
        # self.get_all_dev_names()

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

                # essid: str = wifi.bssids[bssid]['essid'] if 'essid' in wifi.bssids[bssid].keys() else '-'
                # signal: str = str(wifi.bssids[bssid]['signal']) if 'signal' in wifi.bssids[bssid].keys() else '-'
                # channel: str = str(wifi.bssids[bssid]['channel']) if 'channel' in wifi.bssids[bssid].keys() else '-'
                # enc: str = str(wifi.bssids[bssid]['enc']) if 'enc' in wifi.bssids[bssid].keys() else '-'
                # cipher: str = str(wifi.bssids[bssid]['cipher']) if 'cipher' in wifi.bssids[bssid].keys() else '-'
                # auth: str = str(wifi.bssids[bssid]['auth']) if 'auth' in wifi.bssids[bssid].keys() else '-'
                # clients: str = str(len(wifi.bssids[bssid]['clients'])) if 'clients' in wifi.bssids[bssid].keys() else '-'
                # rows.append([essid, bssid, signal, channel, enc, cipher, auth, clients])

                rows.append([
                    wifi.bssids[bssid]['essid'],
                    bssid,
                    wifi.bssids[bssid]['signal'],
                    wifi.bssids[bssid]['channel'],
                    wifi.bssids[bssid]['enc'],
                    wifi.bssids[bssid]['cipher'],
                    wifi.bssids[bssid]['auth'],
                    len(wifi.bssids[bssid]['clients'])
                ])
            except AssertionError:
                pass
        return rows

    def exit_func(self, _input):
        print("Bye")


# region Main function
if __name__ == "__main__":

    path.append(dirname(dirname(dirname(abspath(__file__)))))
    from raw_packet.Utils.base import Base
    from raw_packet.Utils.wifi import WiFi
    base: Base = Base()
    wifi: WiFi = WiFi('en0', 11)
    # wifi._sniff()

    titles = ['ESSID', 'BSSID', 'Signal', 'Channel', 'Encryption', 'Cipher', 'Auth', 'Clients']

    try:
        WiFiAttackTool().run()
    except KeyboardInterrupt:
        base.print_info('Exit ....')

    # wifi.set_wifi_channel(11)
    # wifi._sniff(timeout=3, bssid='70:f1:1c:15:15:b8')
    # wifi._sniff(timeout=1000, bssid='70:f1:1c:15:15:b8', client='78:88:6d:da:02:39')

# endregion
