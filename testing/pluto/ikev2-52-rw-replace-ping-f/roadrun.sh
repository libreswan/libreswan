#!/bin/sh
ping -c 4 -q -n 192.1.2.23
ipsec auto --up road-east-x509-ipv4
ping -c 4 -q -n -I 192.0.2.100 192.1.2.23
ipsec whack --trafficstatus
ping -c 1230000 -q -n -f -I 192.0.2.100 192.1.2.23 &
sleep 60
sleep 60
grep -E  'EVENT_SA_EXPIRE|EVENT_SA_REPLACE' OUTPUT/road.pluto.log  | head -9
echo "re-authenticateded. The state number should 3 and 4"
ipsec whack --trafficstatus
# expect only 8 ICMP packets
tcpdump -t -nn -r OUTPUT/swan12.pcap icmp 2>/dev/null |wc -l
echo done
