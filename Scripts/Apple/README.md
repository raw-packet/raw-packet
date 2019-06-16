---
layout: page
title: Apple
permalink: /scripts/apple/
parent: Scripts
---

# Apple attacks

## Script: [apple_mitm.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Apple/apple_mitm.py)

This script automatically finds Apple devices on the local network using an ARP, NMAP or ICMPv6 scan and implements the MiTM attack with the following techniques:
1. ARP Spoofing
1. Second DHCP ACK
1. Predict next DHCP transaction ID
1. Rogue SLAAC/DHCPv6 server
1. NA Spoofing (IPv6)
1. RA Spoofing (IPv6)

```
root@kali:~/raw-packet# python Scripts/Apple/apple_mitm.py -h
usage: apple_mitm.py [-h] [-T TECHNIQUE] [-D DISCONNECT] [-l LISTEN_IFACE]
                     [-d DEAUTH_IFACE] [-0 DEAUTH_PACKETS]
                     [-f PHISHING_DOMAIN] [-p PHISHING_DOMAIN_PATH]
                     [-t TARGET_IP] [-n NEW_IP] [-s] [--kill]
                     [--ipv6_prefix IPV6_PREFIX]

MiTM Apple devices in local network

optional arguments:
  -h, --help            show this help message and exit
  -T TECHNIQUE, --technique TECHNIQUE
                        Set MiTM technique:
                        1. ARP Spoofing
                        2. Second DHCP ACK
                        3. Predict next DHCP transaction ID
                        4. Rogue SLAAC/DHCPv6 server
                        5. NA Spoofing (IPv6)
                        6. RA Spoofing (IPv6)
  -D DISCONNECT, --disconnect DISCONNECT
                        Set device Disconnect technique:
                        1. IPv4 network conflict detection
                        2. Send WiFi deauthentication packets
                        3. Do not disconnect device after MiTM
  -l LISTEN_IFACE, --listen_iface LISTEN_IFACE
                        Set interface name for send DHCPACK packets
  -d DEAUTH_IFACE, --deauth_iface DEAUTH_IFACE
                        Set interface name for send wifi deauth packets
  -0 DEAUTH_PACKETS, --deauth_packets DEAUTH_PACKETS
                        Set number of deauth packets (default: 5)
  -f PHISHING_DOMAIN, --phishing_domain PHISHING_DOMAIN
                        Set domain name for social engineering (default="auth.apple.wi-fi.com")
  -p PHISHING_DOMAIN_PATH, --phishing_domain_path PHISHING_DOMAIN_PATH
                        Set local path to for social engineering site 
                        in directory: raw_packet/Utils/Phishing_domains 
                        or use your own directory (default="apple")
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -n NEW_IP, --new_ip NEW_IP
                        Set new IP address for target
  -s, --nmap_scan       Use nmap for Apple device detection
  --kill                Kill all processes and threads
  --ipv6_prefix IPV6_PREFIX
                        Set IPv6 network prefix, default - fd00::/64
```

---


## Script: [apple_arp_dos.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Apple/apple_arp_dos.py)

Disconnect Apple device from the local network using ARP packets

```
root@kali:~/raw-packet# python Scripts/Apple/apple_arp_dos.py -h
usage: apple_arp_dos.py [-h] [-i IFACE] [-t TARGET_IP] [-s]

DoS Apple devices in local network with ARP packets

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        Set interface name for send ARP packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -s, --nmap_scan       Use nmap for Apple device detection
```

---

## Script: [apple_rogue_dhcp.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Apple/apple_rogue_dhcp.py)

Rogue DHCP server for Apple device with predict next DHCP transaction ID

```
root@kali:~/raw-packet# python Scripts/Apple/apple_rogue_dhcp.py --help
usage: apple_rogue_dhcp.py [-h] [-i INTERFACE] -t TARGET_MAC -I TARGET_IP [-q]

Rogue DHCP server for Apple devices

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send DHCP reply packets
  -t TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address, required!
  -I TARGET_IP, --target_ip TARGET_IP
                        Set client IP address, required!
  -q, --quiet           Minimal output
```

---
