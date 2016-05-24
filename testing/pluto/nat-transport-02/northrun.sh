ipsec auto --up  north-east-port3
# port 2 does NOT go over ipsec, traffic should remain 0
echo test | nc 192.1.2.23 2
ipsec whack --trafficstatus
# port 3 goes over ipsec, traffic counters should be non-zero
echo test | nc 192.1.2.23 3
ipsec whack --trafficstatus
echo done
