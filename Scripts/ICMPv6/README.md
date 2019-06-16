---
layout: page
title: ICMPv6
permalink: /scripts/icmpv6/
parent: Scripts
---

# ICMPv6

## Script: [icmpv6_scan.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/ICMPv6/icmpv6_scan.py)

Search for hosts that support IPv6 in local network using ICMPv6 protocol

```
root@shakal:~/raw-packet# python Scripts/ICMPv6/icmpv6_scan.py --help
usage: icmpv6_scan.py [-h] [-i INTERFACE] [-m TARGET_MAC] [-t TIMEOUT]
                      [-r RETRY] [-s]

ICMPv6 scanner script

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for ARP scanner
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -t TIMEOUT, --timeout TIMEOUT
                        Set timeout (default=3)
  -r RETRY, --retry RETRY
                        Set number of retry (default=1)
  -s, --router_search   Search router IPv6 link local address
```

---

## Script: [na_spoof.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/ICMPv6/na_spoof.py)

This script implements Neighbor Advertisement spoofing attack

```
usage: na_spoof.py [-h] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC]
                   [-g GATEWAY_IP] [-d DNS_IP] [-q]

NA (Neighbor Advertisement) spoofing

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send ARP packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IPv6 link local address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -g GATEWAY_IP, --gateway_ip GATEWAY_IP
                        Set gateway IPv6 link local address
  -d DNS_IP, --dns_ip DNS_IP
                        Set DNS server IPv6 link local address
  -q, --quiet           Minimal output
```

---

## Script: [ra_spoof.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/ICMPv6/ra_spoof.py)

This script implements Router Advertisement spoofing attack

```
usage: ra_spoof.py [-h] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC]
                   [-g GATEWAY_IP] [-p IPV6_PREFIX] [-d DNS_IP]
                   [-n DNS_DOMAIN_SEARCH] [-q]

RA (Router Advertisement) spoofing

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send ARP packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IPv6 link local address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -g GATEWAY_IP, --gateway_ip GATEWAY_IP
                        Set gateway IPv6 link local address
  -p IPV6_PREFIX, --ipv6_prefix IPV6_PREFIX
                        Set IPv6 prefix, default="fde4:8dba:82e1:ffff::/64"
  -d DNS_IP, --dns_ip DNS_IP
                        Set DNS server IPv6 link local address
  -n DNS_DOMAIN_SEARCH, --dns_domain_search DNS_DOMAIN_SEARCH
                        Set DNS domain search; default: "local"
  -q, --quiet           Minimal output
  ```
---
