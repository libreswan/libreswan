ipsec whack --name road-eastnet-forceencaps --initiate
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
