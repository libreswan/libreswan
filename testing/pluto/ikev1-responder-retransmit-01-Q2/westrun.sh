ipsec auto --up  westnet-eastnet
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# check we didnt fail on retransmits from east
grep "message ignored because it contains a payload type" /tmp/pluto.log
echo done
