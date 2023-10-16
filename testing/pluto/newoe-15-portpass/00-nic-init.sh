#/usr/sbin/named
iptables -F
tcpdump -i eth1 -l -A > /tmp/nic.tcpdump.log 2>&1 & echo $? > /tmp/nic.tcpdump.pid ; sleep 1
