Raw-packet project
===================

[![Official site][site-label]][site-link]
[![Required OS][os-label]][os-link]
[![Python3 version][python3-versions-label]][python3-versions-link]
[![License][license-label]][license-link]
[![Version][version-label]][version-link]
[![Stability][stability-label]][stability-link]

[site-label]: https://raw-packet.github.io/static/images/labels/site.svg
[site-link]: https://raw-packet.github.io/
[os-label]: https://raw-packet.github.io/static/images/labels/os.svg
[os-link]: https://en.wikipedia.org/wiki/Operating_system
[python3-versions-label]: https://raw-packet.github.io/static/images/labels/python3.svg
[python3-versions-link]: https://www.python.org/downloads/release/python-360/
[license-label]: https://raw-packet.github.io/static/images/labels/license.svg
[license-link]: https://github.com/raw-packet/raw-packet/blob/master/LICENSE
[version-label]: https://raw-packet.github.io/static/images/labels/version.svg
[version-link]: https://github.com/raw-packet/raw-packet/releases
[stability-label]: https://raw-packet.github.io/static/images/labels/stability.svg
[stability-link]: https://github.com/raw-packet/raw-packet/releases

[![Logo](https://raw-packet.github.io/static/images/logo/logo-caption.png)](https://raw-packet.github.io/)

---

# Important information
***This project is created only for educational purposes and can not be used for 
law violation or personal gain.<br/>The author of this project is not responsible for any possible harm caused by the materials of this project.***

# Description 
This project implements network protocols such as Ethernet ARP IPv4 UDP TCP DHCPv4 ICMPv4 IPv6 DHCPv6 ICMPv6 DNS MDNS on raw socket.

---

# Info

Author: [Vladimir Ivanov](https://github.com/Vladimir-Ivanov-Git)

SubAuthors: [Ilja Bulatov](https://github.com/barrracud4)

Project email: [raw.packet.project@gmail.com](mailto:raw.packet.project@gmail.com)

Required OS: Windows, MacOS, Linux

Python minimum versions: [3.6](https://www.python.org/downloads/release/python-360/)

License: [MIT](https://github.com/raw-packet/raw-packet/blob/master/LICENSE)

---

# Install

## Debian based OS install:
```
sudo apt update
sudo apt install -y python3 python3-pip wireless-tools tshark
pip3 install --upgrade pip
sudo pip3 install raw-packet
```

## MacOS install:

#### 1. Install Homebrew:
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

#### 2. Adding repository to Homebrew:
```
brew tap raw-packet/raw-packet
```

#### 3. Install Raw-packet:
```
brew install raw-packet
```

## Windows install:

#### 1. Install [Wireshark](https://www.wireshark.org/download.html)

#### 2. Install [Python 3.8](https://www.microsoft.com/en-us/p/python-38/9mssztt1n39l)

#### 3. Install Raw-packet:
```
pip3 install --upgrade pip
pip3 install raw-packet
```

---

## Publications (on russian)

- [Apple security updates](https://support.apple.com/en-us/HT209341)

- [PHDays: Apple, all about MiTM](https://www.phdays.com/en/program/reports/apple-all-about-mitm/)

- [Yandex IT SEC 2018: Apple vs DHCP](https://events.yandex.ru/lib/talks/5519/)

- [Xakep.ru: Advanced Wi-Fi MiTM](https://xakep.ru/2017/09/25/wifi-mitm-advanced/)

- [Attacking DHCP](https://habrahabr.ru/company/dsec/blog/333978/)

- [Attacking DHCP part 2: Wi-Fi](https://habrahabr.ru/post/338860/)

- [Attacking DHCP part 3: Apple](https://habrahabr.ru/post/338864/)

- [Attacking DHCP part 4: Apple + ARP](https://habrahabr.ru/post/339666/)

---

## Performance 

This project was designed specifically to improve the performance and speed of requests needed for network attacks.

On Linux you can compare perfomance of this project with popular python library [SCAPY](https://scapy.net/) via script [time_test.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Others/time_test.py)

Our testing you can see bellow

| Number of Packets                          | 10                | 100              | 1000            | 10000         |
|--------------------------------------------|-------------------|------------------|-----------------|---------------|
| ARP requests in Scapy (sec)                | 0,0522048473358   | 0,0785529613495  | 0,302206039429  | 2,95294880867 |
| ARP requests in Raw-packet (sec)           | 0,00202298164368  | 0,00270104408264 | 0,090922832489  | 1,3037519455  |
| DHCP discover requests in Scapy (sec)      | 0,397399187088    | 4,16092181206    | 39,5892789364   |       -       |
| DHCP discover requests in Raw-packet (sec) | 0,00177597999573  | 0,0219049453735  | 0,162989854813  |       -       |
| DNS requests in Scapy (sec)                | 0.608256101608    | 6.05325508118    | 58.4151289463   |       -       |
| DNS requests in Raw-packet (sec)           | 0.00274395942688  | 0.0127770900726  | 0.0796978473663 |       -       |


![Scapy vs. Raw-packet ARP requests](https://raw-packet.github.io/static/images/others/ARP_requests_timing.png)

![Scapy vs. Raw-packet DHCP discover requests](https://raw-packet.github.io/static/images/others/DHCP_discover_requests_timing.png)

![Scapy vs. Raw-packet DNS requests](https://raw-packet.github.io/static/images/others/DNS_requests_timing.png)

---

# Scripts

# Apple attacks

## Script: [apple_mitm](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/Apple/apple_mitm.py)

This script automatically finds Apple devices on the local network using an ARP, NMAP or ICMPv6 scan and implements the MiTM attack with the following techniques:
1. ARP Spoofing
1. Second DHCP ACK
1. Predict next DHCP transaction ID
1. Rogue SLAAC/DHCPv6 server
1. NA Spoofing (IPv6)
1. RA Spoofing (IPv6)

```
root@kali:~# apple_mitm --help
usage: apple_mitm [-h] [-T TECHNIQUE] [-D DISCONNECT] [-P PHISHING_SITE] [-i MITM_IFACE]
                  [-d DEAUTH_IFACE] [-0 DEAUTH_PACKETS] [-g4 GATEWAY_IPV4] [-g6 GATEWAY_IPV6]
                  [-d4 DNS_IPV4] [-d6 DNS_IPV6] [-m TARGET_MAC] [-t4 TARGET_IPV4]
                  [-n4 TARGET_NEW_IPV4] [-t6 TARGET_IPV6] [-n6 TARGET_NEW_IPV6]
                  [--ipv6_prefix IPV6_PREFIX]
                                                                                                
            MiTM Apple devices (apple_mitm)

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
  -P PHISHING_SITE, --phishing_site PHISHING_SITE
                        Set Phishing site "apple", "google" or Path to your site
  -i MITM_IFACE, --mitm_iface MITM_IFACE
                        Set interface name for MiTM
  -d DEAUTH_IFACE, --deauth_iface DEAUTH_IFACE
                        Set interface name for send wifi deauth packets
  -0 DEAUTH_PACKETS, --deauth_packets DEAUTH_PACKETS
                        Set number of deauth packets (default: 25)
  -g4 GATEWAY_IPV4, --gateway_ipv4 GATEWAY_IPV4
                        Set gateway IPv4 address
  -g6 GATEWAY_IPV6, --gateway_ipv6 GATEWAY_IPV6
                        Set gateway IPv6 address
  -d4 DNS_IPV4, --dns_ipv4 DNS_IPV4
                        Set DNS server IPv4 address
  -d6 DNS_IPV6, --dns_ipv6 DNS_IPV6
                        Set DNS server IPv6 address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -t4 TARGET_IPV4, --target_ipv4 TARGET_IPV4
                        Set target IPv4 address
  -n4 TARGET_NEW_IPV4, --target_new_ipv4 TARGET_NEW_IPV4
                        Set new IPv4 address for target
  -t6 TARGET_IPV6, --target_ipv6 TARGET_IPV6
                        Set link local target IPv6 address
  -n6 TARGET_NEW_IPV6, --target_new_ipv6 TARGET_NEW_IPV6
                        Set new global IPv6 address for target
  --ipv6_prefix IPV6_PREFIX
                        Set IPv6 network prefix, default - fde4:8dba:82e1:ffff::/64
```

### Sample script output:
![apple_mitm output](https://raw-packet.github.io/static/images/screenshots/apple_mitm_screenshot.png)

---

## Script: [apple_arp_dos](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/Apple/apple_arp_dos.py)

Disconnect Apple device from the local network using ARP packets

```
root@kali:~# apple_arp_dos --help
usage: apple_arp_dos [-h] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC] [-q]

Disconnect Apple device in local network with ARP packets (apple_arp_dos)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set network interface name
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IPv4 address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -q, --quiet           Minimal output
```

### Sample script output:
![apple_arp_dos output](https://raw-packet.github.io/static/images/screenshots/apple_arp_dos_screenshot.png)

---

## Script: [apple_dhcp_server.py](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/Apple/apple_dhcp_server.py)

Rogue DHCPv4 server for Apple device with predict next DHCPv4 transaction ID

```
root@kali:~# apple_dhcp_server --help
usage: apple_dhcp_server [-h] [-i INTERFACE] -t TARGET_IP -m TARGET_MAC [-b] [-q]

Rogue DHCPv4 server for Apple devices (apple_dhcp_server)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set network interface name
  -t TARGET_IP, --target_ip TARGET_IP
                        Set new IPv4 address for target
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -b, --broadcast       Send broadcast DHCPv4 responses
  -q, --quiet           Minimal output
```

### Sample script output:
![apple_dhcp_server output](https://raw-packet.github.io/static/images/screenshots/apple_dhcp_server_screenshot.png)

---

# ARP

The [Address Resolution Protocol (ARP)](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) is a communication protocol used for discovering the link layer address, such as a MAC address, associated with a given internet layer address, typically an IPv4 address.

---

## Script: [arp_scan](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/ARP/arp_scan.py)
This script creates and sends ARP requests (Who has?) to search for alive hosts on the local network.

```
root@kali:~# arp_scan --help
usage: arp_scan [-h] [-i INTERFACE] [-t TARGET_IP] [--timeout TIMEOUT] [--retry RETRY]

                ARP Scanner (arp_scan)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for ARP scanner
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IPv4 address
  --timeout TIMEOUT     Set timeout (default=5)
  --retry RETRY         Set number of retry packets (default=5)
```

### Sample script output:
![arp_scan output](https://raw-packet.github.io/static/images/screenshots/arp_scan_screenshot.png)

---

## Script: [arp_spoof](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/ARP/arp_spoof.py)

This script implement the ARP spoofing attack. 
ARP spoofing, ARP cache poisoning or ARP poison routing, is a technique that  an attacker sends fake (spoofed) Address Resolution Protocol (ARP) messages onto a local network.

```
root@kali:~# arp_spoof --help
usage: arp_spoof [-h] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC] [-g GATEWAY_IP] [-r] [--ipv4_multicast]
                 [--ipv6_multicast] [--broadcast] [-q]

               ARP Spoofing (arp_spoof)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send ARP packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -g GATEWAY_IP, --gateway_ip GATEWAY_IP
                        Set gateway IP address
  -r, --requests        Send only ARP requests
  --ipv4_multicast      Send ARP replies/requests to IPv4 multicast MAC address
  --ipv6_multicast      Send ARP replies/requests to IPv6 multicast MAC address
  --broadcast           Send ARP replies/requests to broadcast MAC address
  -q, --quiet           Minimal output
```

### Sample script output:
![arp_spoof output](https://raw-packet.github.io/static/images/screenshots/arp_spoof_screenshot.png)

---

# DHCPv4

The [Dynamic Host Configuration Protocol (DHCP)](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) is a network management protocol used on UDP/IP networks whereby a DHCP server dynamically assigns an IP address and other network configuration parameters to each device on a network so they can communicate with other IP networks.

## Script: [dhcpv4_server](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/DHCPv4/dhcpv4_server.py)

This script implements an attack on network clients by using fake DHCPv4 server which answers with malicius configuration faster than legitimate DHCPv4 server. 
This attack also known as Rogue DHCPv4 Server Attack.

```
root@kali:~# dhcpv4_server --help
usage: dhcpv4_server [-h] [-i INTERFACE] [-f FIRST_OFFER_IP] [-l LAST_OFFER_IP]
                     [-m TARGET_MAC] [-t TARGET_IP] [--netmask NETMASK]
                     [--dhcp_mac DHCP_MAC] [--dhcp_ip DHCP_IP] [--router ROUTER]
                     [--dns DNS] [--tftp TFTP] [--wins WINS] [--domain DOMAIN]
                     [--lease_time LEASE_TIME] [--discover] [-O SHELLSHOCK_OPTION_CODE]
                     [-c SHELLSHOCK_COMMAND] [-b] [-p BIND_PORT] [-N] [-E] [-R]
                     [-e REVERSE_PORT] [-n] [-B] [--ip_path IP_PATH]
                     [--iface_name IFACE_NAME] [--broadcast_response] [--dnsop] [--exit]
                     [--apple] [-q]

             DHCPv4 server (dhcpv4_server)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send reply packets
  -f FIRST_OFFER_IP, --first_offer_ip FIRST_OFFER_IP
                        Set first client ip for offering
  -l LAST_OFFER_IP, --last_offer_ip LAST_OFFER_IP
                        Set last client ip for offering
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -t TARGET_IP, --target_ip TARGET_IP
                        Set client IP address with MAC in --target_mac
  --netmask NETMASK     Set network mask
  --dhcp_mac DHCP_MAC   Set DHCP server MAC address, if not set use your MAC address
  --dhcp_ip DHCP_IP     Set DHCP server IP address, if not set use your IP address
  --router ROUTER       Set router IP address, if not set use your ip address
  --dns DNS             Set DNS server IP address, if not set use your ip address
  --tftp TFTP           Set TFTP server IP address
  --wins WINS           Set WINS server IP address
  --domain DOMAIN       Set domain name for search, default=local
  --lease_time LEASE_TIME
                        Set lease time, default=172800
  --discover            Send DHCP discover packets in the background thread
  -O SHELLSHOCK_OPTION_CODE, --shellshock_option_code SHELLSHOCK_OPTION_CODE
                        Set dhcp option code for inject shellshock payload, default=114
  -c SHELLSHOCK_COMMAND, --shellshock_command SHELLSHOCK_COMMAND
                        Set shellshock command in DHCP client
  -b, --bind_shell      Use awk bind tcp shell in DHCP client
  -p BIND_PORT, --bind_port BIND_PORT
                        Set port for listen bind shell (default=1234)
  -N, --nc_reverse_shell
                        Use nc reverse tcp shell in DHCP client
  -E, --nce_reverse_shell
                        Use nc -e reverse tcp shell in DHCP client
  -R, --bash_reverse_shell
                        Use bash reverse tcp shell in DHCP client
  -e REVERSE_PORT, --reverse_port REVERSE_PORT
                        Set port for listen bind shell (default=443)
  -n, --without_network
                        Do not add network configure in payload
  -B, --without_base64  Do not use base64 encode in payload
  --ip_path IP_PATH     Set path to "ip" in shellshock payload, default = /bin/
  --iface_name IFACE_NAME
                        Set iface name in shellshock payload, default = eth0
  --broadcast_response  Send broadcast response
  --dnsop               Do not send DHCP OFFER packets
  --exit                Exit on success MiTM attack
  --apple               Add delay before send DHCP ACK
  -q, --quiet           Minimal output
```

### Sample script output:
![dhcpv4_server output](https://raw-packet.github.io/static/images/screenshots/dhcpv4_server_screenshot.png)

---

# DHCPv6

The [Dynamic Host Configuration Protocol version 6 (DHCPv6)](https://en.wikipedia.org/wiki/DHCPv6) is a network protocol for configuring Internet Protocol version 6 (IPv6) hosts with IP addresses, IP prefixes and other configuration data required to operate in an IPv6 network. It is the IPv6 equivalent of the Dynamic Host Configuration Protocol for IPv4.

## Script: [dhcpv6_server](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/DHCPv6/dhcpv6_server.py)

This script implements fake DHCPv6 server for perfom SLAAC attack/Rogue DHCPv6.

```
root@kali:~# dhcpv6_server --help
usage: dhcpv6_server [-h] [-i INTERFACE] [-p PREFIX] [-f FIRST_SUFFIX] [-l LAST_SUFFIX]
                     [-t TARGET_MAC] [-T TARGET_IPV6] [-D] [-d DNS] [-s DNS_SEARCH]
                     [--delay DELAY] [-q]

          SLAAC/DHCPv6 server (dhcpv6_server)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send reply packets
  -p PREFIX, --prefix PREFIX
                        Set network prefix
  -f FIRST_SUFFIX, --first_suffix FIRST_SUFFIX
                        Set first suffix client IPv6 for offering
  -l LAST_SUFFIX, --last_suffix LAST_SUFFIX
                        Set last suffix client IPv6 for offering
  -t TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -T TARGET_IPV6, --target_ipv6 TARGET_IPV6
                        Set client Global IPv6 address with MAC --target_mac
  -D, --disable_dhcpv6  Do not use DHCPv6 protocol
  -d DNS, --dns DNS     Set recursive DNS IPv6 address
  -s DNS_SEARCH, --dns_search DNS_SEARCH
                        Set DNS search domain
  --delay DELAY         Set delay between packets
  -q, --quiet           Minimal output
```

### Sample script output:
![dhcpv6_server output](https://raw-packet.github.io/static/images/screenshots/dhcpv6_server_screenshot.png)

---

# DNS

## Script: [dns_server](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/DNS/dns_server.py)

This script impelements a simple DNS server (like a [dnschef](https://github.com/iphelix/dnschef)), which is useful in MiTM attacks. You can setup A or AAAA records for several domains. 

```
root@kali:~# dns_server -h
usage: dns_server [-h] [-i INTERFACE] [-p PORT] [-t TARGET_MAC] [--T4 T4] [--T6 T6]
                  [-c CONFIG_FILE] [--fake_domains FAKE_DOMAINS]
                  [--no_such_domains NO_SUCH_DOMAINS] [--fake_ipv4 FAKE_IPV4]
                  [--fake_ipv6 FAKE_IPV6] [--ipv6] [--disable_ipv4]
                  [--log_file_name LOG_FILE_NAME] [--log_file_format LOG_FILE_FORMAT] [-f]
                  [-q]

                DNS server (dns_server)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send DNS reply packets
  -p PORT, --port PORT  Set UDP port for listen DNS request packets (default: 53)
  -t TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  --T4 T4               Set target IPv4 address
  --T6 T6               Set target IPv6 address
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Set json config file name, example: --config_file
                        "dns_server_config.json"
  --fake_domains FAKE_DOMAINS
                        Set fake domain regexp or domains, example: --fake_domains
                        ".*apple.com,.*google.com"
  --no_such_domains NO_SUCH_DOMAINS
                        Set no such domain or domains, example: --no_such_domains
                        "apple.com,google.com"
  --fake_ipv4 FAKE_IPV4
                        Set fake IP address or addresses, example: --fake_ipv4
                        "192.168.0.1,192.168.0.2"
  --fake_ipv6 FAKE_IPV6
                        Set fake IPv6 address or addresses, example: --fake_ipv6
                        "fd00::1,fd00::2"
  --ipv6                Enable IPv6
  --disable_ipv4        Disable IPv4
  --log_file_name LOG_FILE_NAME
                        Set file name for save DNS queries (default: "dns_server_log")
  --log_file_format LOG_FILE_FORMAT
                        Set file format for save results: csv, xml, json, txt (default:
                        "json")
  -f, --fake_answer     Set your IPv4 or IPv6 address in all answers
  -q, --quiet           Minimal output
```

### Sample script configuration:
```json
{
  ".*google.com": {
    "A": ["192.168.0.1", "192.168.0.2"],
    "AAAA": "fd00::1",
    "NS": ["ns1.google.com", "ns2.google.com"],
    "MX": "mail.google.com"
  },
  ".*apple.com": {
    "A": "192.168.0.1",
    "AAAA": ["fd00::1", "fd00::2"],
    "NS": "ns.apple.com",
    "MX": ["mail1.apple.com", "mail2.apple.com"]
  },
  "gooogle.com": {
    "no such domain": true
  },
  "evil.com": {
    "success": true,
    "A": "my ipv4 address",
    "AAAA": "my ipv6 address"
  }
}
```

### Sample script output (without parameters):
![dns_server.py output](https://raw-packet.github.io/static/images/screenshots/dns_server_screenshot.png)

### Sample script output (fake answer):
![dns_server.py output_fake_answer](https://raw-packet.github.io/static/images/screenshots/dns_server_screenshot_fake_answer.png)

---

# ICMPv4

## Script: [icmpv4_redirect](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/ICMPv4/icmpv4_redirect.py)

This script implement the ICMPv4 redirect attack. 

```
root@kali:~# icmpv4_redirect --help
usage: icmpv4_redirect [-h] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC] [-g GATEWAY_IP]
                       [-r REDIRECT_IP] [-q]

           ICMPv4 redirect (icmpv4_redirect)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send ICMP redirect packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IPv4 address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -g GATEWAY_IP, --gateway_ip GATEWAY_IP
                        Set gateway IPv4 address (default: <your_ipv4_gateway>)
  -r REDIRECT_IP, --redirect_ip REDIRECT_IP
                        Set IP addresses where to redirect (example: "1.1.1.1,8.8.8.8")
  -q, --quiet           Minimal output
```

### Sample script output:
![icmpv4_redirect output](https://raw-packet.github.io/static/images/screenshots/icmpv4_redirect_screenshot.png)

---

# IPv6

## Script: [ipv6_scan.py](https://github.com/raw-packet/raw-packet/blob/testing/raw_packet/Scripts/IPv6/ipv6_scan.py)

Search for hosts that support IPv6 in local network using ICMPv6 protocol

```
root@kali:~# ipv6_scan --help
usage: ipv6_scan [-h] [-i INTERFACE] [-m TARGET_MAC] [-t TIMEOUT] [-r RETRY] [-s]

               ICMPv6 scan (icmpv6_scan)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for ARP scanner
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  -t TIMEOUT, --timeout TIMEOUT
                        Set timeout (default=5)
  -r RETRY, --retry RETRY
                        Set number of retry (default=5)
  -s, --router_search   Search router IPv6 link local address
```

### Sample script output:
![ipv6_scan output](https://raw-packet.github.io/static/images/screenshots/ipv6_scan_screenshot.png)

### Search IPv6 router
![ipv6_router_search output](https://raw-packet.github.io/static/images/screenshots/ipv6_scan_router_search_screenshot.png)

---

## Script: [ipv6_spoof](https://github.com/raw-packet/raw-packet/blob/testing/raw_packet/Scripts/IPv6/ipv6_spoof.py)

This script implements Router Advertisement and Neighbor Advertisement spoofing attack

```
root@kali:~# ipv6_spoof --help
usage: ipv6_spoof [-h] [-T TECHNIQUE] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC]
                  [-g GATEWAY_IP] [-p IPV6_PREFIX] [-d DNS_IP] [-n DNS_DOMAIN_SEARCH] [-q]

              IPv6 Spoofing (ipv6_spoof)

optional arguments:
  -h, --help            show this help message and exit
  -T TECHNIQUE, --technique TECHNIQUE
                        Set ICMPv6 MiTM technique (example: 1)
                        1. ICMPv6 RA (Router Advertisement) Spoofing
                        2. ICMPv6 NA (Neighbor Advertisement) Spoofing
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

## Router Advertisement spoofing

### Sample script output:
![ipv6_spoof_ra output](https://raw-packet.github.io/static/images/screenshots/ipv6_spoof_ra_screenshot.png)

## Neighbor Advertisement spoofing

### Sample script output:
![ipv6_spoof_na output](https://raw-packet.github.io/static/images/screenshots/ipv6_spoof_na_screenshot.png)

---

# Network Conflict Creator (ncc)

## Script: [ncc](https://github.com/raw-packet/raw-packet/blob/testing/raw_packet/Scripts/NCC/ncc.py)

Script for creating network conflicts for varius testing.

```
root@kali:~# ncc --help
usage: ncc [-h] [-i INTERFACE] [-t TARGET_IP] [-m TARGET_MAC] [--replies] [--requests]
           [--broadcast] [-p PACKETS] [-q] [-e]

            Network Conflict Creator (ncc)

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for listen and send packets
  -t TARGET_IP, --target_ip TARGET_IP
                        Set target IP address
  -m TARGET_MAC, --target_mac TARGET_MAC
                        Set target MAC address
  --replies             Send only ARP replies
  --requests            Send only ARP requests
  --broadcast           Send broadcast ARP requests
  -p PACKETS, --packets PACKETS
                        Number of ARP packets (default: 10)
  -q, --quiet           Minimal output
  -e, --exit            Exit on success
```

### Sample script output:
![ncc output](https://raw-packet.github.io/static/images/screenshots/ncc_screenshot.png)

---

# Network Security Check (nsc)

## Script: [nsc](https://github.com/raw-packet/raw-packet/blob/master/raw_packet/Scripts/NSC/nsc.py)

### Checking network security mechanisms
1. Works on Windows, MacOS and Linux
1. Check ARP Spoofing
1. Check ICMPv4 Redirect 
1. Check Rogue DHCPv4
1. Check ICMPv6 Redirect 
1. Check ICMPv6 Router Advertisement Spoofing
1. Check ICMPv6 Neighbor Advertisement Spoofing
1. Check Rogue DHCPv6
1. Check STP spoofing

```
root@kali:~# nsc --help
usage: nsc [-h] [-i SEND_INTERFACE] [-l LISTEN_INTERFACE] [-n TEST_HOST_INTERFACE]
           [-t TEST_HOST_IP] [-m TEST_HOST_MAC] [-o TEST_HOST_OS] [-u TEST_SSH_USER]
           [-p TEST_SSH_PASS] [-k TEST_SSH_PKEY] [-G GATEWAY_IP] [-g GATEWAY_MAC]
           [-r NUMBER_OF_PACKETS] [-L LISTEN_TIME] [-q]

             Network Security Check (nsc)

optional arguments:
  -h, --help            show this help message and exit
  -i SEND_INTERFACE, --send_interface SEND_INTERFACE
                        Set interface name for send packets
  -l LISTEN_INTERFACE, --listen_interface LISTEN_INTERFACE
                        Set interface name for listen packets
  -n TEST_HOST_INTERFACE, --test_host_interface TEST_HOST_INTERFACE
                        Set test host network interface for listen packets
  -t TEST_HOST_IP, --test_host_ip TEST_HOST_IP
                        Set test host IP address for ssh connection
  -m TEST_HOST_MAC, --test_host_mac TEST_HOST_MAC
                        Set test host MAC address for ssh connection
  -o TEST_HOST_OS, --test_host_os TEST_HOST_OS
                        Set test host OS (MacOS, Linux, Windows)
  -u TEST_SSH_USER, --test_ssh_user TEST_SSH_USER
                        Set test host user name for ssh connection
  -p TEST_SSH_PASS, --test_ssh_pass TEST_SSH_PASS
                        Set test host password for ssh connection
  -k TEST_SSH_PKEY, --test_ssh_pkey TEST_SSH_PKEY
                        Set test host private key for ssh connection
  -G GATEWAY_IP, --gateway_ip GATEWAY_IP
                        Set gateway IPv4 address
  -g GATEWAY_MAC, --gateway_mac GATEWAY_MAC
                        Set gateway MAC address
  -r NUMBER_OF_PACKETS, --number_of_packets NUMBER_OF_PACKETS
                        Set number of spoofing packets for each test (default: 10)
  -L LISTEN_TIME, --listen_time LISTEN_TIME
                        Set time to listen spoofing packets in seconds (default: 60)
  -q, --quiet           Minimal output
```

### Sample script output:
![nsc output](https://raw-packet.github.io/static/images/screenshots/nsc_kali_screenshot.png)

### Sample script output (test host):
![nsc output](https://raw-packet.github.io/static/images/screenshots/nsc_kali_test_host_screenshot.png)

---

# WiFi

## Script: [wat](https://github.com/raw-packet/raw-packet/blob/testing/raw_packet/Scripts/WiFi/wat.py)

### Cross-platform WiFi attack tool (wat)
1. Works on MacOS and Linux
1. Collects wireless AP information
1. Sends association packets
1. Sends deauthentication packets
1. Switch between WiFi channels
1. Saves WPA handshakes in formats: pcap, hccapx, 22000
1. Supports PMKID (AP clientless attack)
1. Saves WPA RSN PMKID in format for hashcat brute
1. Supports vulnerability CVE-2019-15126 kr00k (decryption of CCMP packet with NULL 128 bits - temporary key)

```
root@kali:~# wat --help
usage: wat [-h] [-i INTERFACE] [-c CHANNEL] [-d]

         Cross platform WiFi attack tool (wat)

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
  -d, --debug           Maximum output
```

### Sample script output:
![wat output](https://raw-packet.github.io/static/images/screenshots/wat_screenshot.png)

### Video demo:
[![wat demo video](https://raw-packet.github.io/static/images/gifs/attack_tool.gif)](https://youtu.be/IcZVmDHQvLE)

---
