#/usr/sbin/named
iptables -F
( tcpdump -i eth1 -l -A & echo $? > /tmp/nic.tcpdump.pid ) > /tmp/nic.tcpdump.log 2>&1
