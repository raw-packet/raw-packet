---
layout: page
title: Miscellaneous
permalink: /scripts/misc/
parent: Scripts
---

# Miscellaneous scripts

## Script: [network_conflict_creator.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Others/network_conflict_creator.py)

Script for creating network conflicts for varius testing.

```
root@shakal:~/raw-packet# python Scripts/Others/network_conflict_creator.py --help
usage: network_conflict_creator.py [-h] [-i INTERFACE] -t TARGET_IP
                                   [-m TARGET_MAC] [-a] [-r] [-p PACKETS] [-q]

Network conflict creator script

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for listen and send packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -a, --answers         Send only ARP answers
  -r, --requests        Send only ARP requests
  -p PACKETS, --packets PACKETS
                        Number of ARP answer packets (default: 10)
  -q, --quiet           Minimal output
```


---

## Script: [sniff_test.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Others/sniff_test.py)

**Under Construction**

---

## Script: [time_test.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Others/time_test.py)

**Under Construction**

---
