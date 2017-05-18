from base import Ethernet, IP

eth = Ethernet()
ip = IP()

print eth.get_random_mac()

print ":".join("{:02x}".format(ord(c)) for c in eth.make_header("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", 2048))

print ip.get_random_ip()

print ":".join("{:02x}".format(ord(c)) for c in ip.make_header("127.0.0.1", "127.0.0.1", 0, 1))

