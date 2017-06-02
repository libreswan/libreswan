# this connections auto=start on east
# ipsec auto --up westnet-eastnet-ikev2a
# give time to establish the first connection
sleep 15
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec auto --up westnet-eastnet-ikev2b
ping -n -c 4 -I 192.0.100.254 192.0.200.254
ipsec whack --trafficstatus
echo done
