from base import Ethernet, IP, UDP

eth = Ethernet()
ip = IP()
udp = UDP()

print eth.get_random_mac()

print ":".join("{:02x}".format(ord(c)) for c in eth.make_header("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", 2048))

print ip.get_random_ip()

print ":".join("{:02x}".format(ord(c)) for c in ip.make_header("127.0.0.1", "127.0.0.1", 0, 8, 1))

print ":".join("{:02x}".format(ord(c)) for c in udp.make_header(12345, 53, 0))

