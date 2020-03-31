# WiFi

## Script: [attack_tool.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/WiFi/attack_tool.py)

### Cross platform WiFi attack tool
1. Work on MacOS and Linux
1. Collect information about wireless AP
1. Send deauth and association packets
1. Switch between WiFi channels
1. Save WPA handshakes in formats: pcap, hccapx, 22000
1. Support PMKID (attack AP without clients)
1. Save WPA RSN PMKID in format for hashcat brute
1. Support CVE-2019-15126 kr00k vulnerability (Decrypt CCMP packet with NULL 128 bits – Temporal Key)

```
root@kali:~/raw-packet# python3 Scripts/WiFi/attack_tool.py -h
usage: attack_tool.py [-h] [-i INTERFACE] [-c CHANNEL]

Cross platform WiFi attack tool

Ctrl-E Show Wireless access point information
Ctrl-D Send IEEE 802.11 deauth packets
Ctrl-D Switch WiFi channel
Ctrl-A Send IEEE 802.11 association packet
Ctrl-R Start scanner (switch between WiFi channels)
Ctrl-H Show help information
Ctrl-C Exit

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set wireless interface name for sniff packets
  -c CHANNEL, --channel CHANNEL
                        Set WiFi channel
```

### Sample script output:
![attack_tool.py output](https://raw-packet.github.io/static/images/screenshots/attack_tool.py_screenshot.png)

---
