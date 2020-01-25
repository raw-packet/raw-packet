# DNS

## Script: [dns_server.py](https://github.com/raw-packet/raw-packet/blob/master/Scripts/DNS/dns_server.py)

This script impelements a simple DNS server (like a [dnschef](https://github.com/iphelix/dnschef)), which is useful in MiTM attacks. You can setup A or AAAA records for several domains. 

```
root@kali:~/raw-packet# python3 Scripts/DNS/dns_server.py --help
usage: dns_server.py [-h] [-i INTERFACE] [-p PORT] [-t TARGET_MAC] [--T4 T4]
                     [--T6 T6] [-c CONFIG_FILE] [--fake_domains FAKE_DOMAINS]
                     [--no_such_domains NO_SUCH_DOMAINS]
                     [--fake_ipv4 FAKE_IPV4] [--fake_ipv6 FAKE_IPV6] [--ipv6]
                     [--disable_ipv4] [--log_file_name LOG_FILE_NAME]
                     [--log_file_format LOG_FILE_FORMAT] [-f] [-q]

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
  -c CONFIG_FILE, --config_file CONFIG_FILE
                        Set json config file name, example: --config_file
                        "dns_server_config.json"
  --fake_domains FAKE_DOMAINS
                        Set fake domain regexp or domains, example:
                        --fake_domains ".*apple.com,.*google.com"
  --no_such_domains NO_SUCH_DOMAINS
                        Set no such domain or domains, example:
                        --no_such_domains "apple.com,google.com"
  --fake_ipv4 FAKE_IPV4
                        Set fake IP address or addresses, example: --fake_ipv4
                        "192.168.0.1,192.168.0.2"
  --fake_ipv6 FAKE_IPV6
                        Set fake IPv6 address or addresses, example:
                        --fake_ipv6 "fd00::1,fd00::2"
  --ipv6                Enable IPv6
  --disable_ipv4        Disable IPv4
  --log_file_name LOG_FILE_NAME
                        Set file name for save DNS queries (default:
                        "dns_server_log")
  --log_file_format LOG_FILE_FORMAT
                        Set file format for save results: csv, xml, json, txt
                        (default: "json")
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
![dns_server.py output](https://raw-packet.github.io/static/images/screenshots/dns_server.py_screenshot.png)

### Sample script output (fake answer):
![dns_server.py output_fake_answer](https://raw-packet.github.io/static/images/screenshots/dns_server.py_screenshot_fake_answer.png)

---
