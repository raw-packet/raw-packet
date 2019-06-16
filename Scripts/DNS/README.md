---
layout: page
title: DNS
permalink: /scripts/dns/
parent: Scripts
---

# DNS

## Script: [dns_server.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/DNS/dns_server.py)

This script impelements a simple DNS server (like a [dnschef](https://github.com/iphelix/dnschef)), which is useful in MiTM attacks. You can setup A or AAAA records for several domains. 

```
root@shakal:~/raw-packet# python Scripts/DNS/dns_server.py --help
usage: dns_server.py [-h] [-i INTERFACE] [-p PORT] [-t TARGET_MAC] [--T4 T4]
                     [--T6 T6] [--fake_domains FAKE_DOMAINS]
                     [--no_such_names NO_SUCH_NAMES] [--fake_ip FAKE_IP]
                     [--fake_ipv6 FAKE_IPV6] [--ipv6] [--disable_ipv4] [-f]
                     [-q]

DNS server

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send DNS reply packets
  -p PORT, --port PORT  Set UDP port for listen DNS request packets (default:
                        53)
  -t TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  --T4 T4               Set target IPv4 address
  --T6 T6               Set target IPv6 address
  --fake_domains FAKE_DOMAINS
                        Set fake domain or domains, example: --fake_domains
                        "apple.com,google.com"
  --no_such_names NO_SUCH_NAMES
                        Set no such domain or domains, example:
                        --no_such_names "apple.com,google.com"
  --fake_ip FAKE_IP     Set fake IP address or addresses, example: --fake_ip
                        "192.168.0.1,192.168.0.2"
  --fake_ipv6 FAKE_IPV6
                        Set fake IPv6 address or addresses, example:
                        --fake_ipv6 "fd00::1,fd00::2"
  --ipv6                Enable IPv6
  --disable_ipv4        Disable IPv4
  -f, --fake_answer     Set your IPv4 or IPv6 address in all answers
  -q, --quiet           Minimal output
```

---
