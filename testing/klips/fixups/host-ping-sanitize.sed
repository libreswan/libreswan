s,\(64 bytes from .*: icmp_req=. ttl=64\) time=\(0.[0-9]*\) ms,\1 time=0.XXX ms,
s,\(4 packets transmitted\, 4 received\, 0% packet loss\, time \)\([0-9]*\)ms,\1XXXX,
s,\(rtt min/avg/max/mdev = \).*\( ms\),\10.XXX/0.XXX/0.XXX/0.XXX\2,

