ipsec auto --up  westnet-eastnet-ikev1
ping -n -c 4 192.1.2.23
ipsec whack --trafficstatus
echo done
