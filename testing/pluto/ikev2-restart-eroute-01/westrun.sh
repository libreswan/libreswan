ipsec auto --up westnet-eastnet-default
sleep 2
ipsec auto --down westnet-eastnet-default
# be generous and give delete some time to notify
sleep 3
# no eroute in use should appear using the other conn
ipsec auto --up westnet-eastnet-zero
echo done
