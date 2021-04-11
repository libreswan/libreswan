ipsec auto --status | grep northnet-eastnets
ipsec auto --up northnet-eastnet
taskset 0x1 ping -n -q -c 2 -I 192.0.3.254 192.0.2.254
taskset 0x2 ping -n -q -c 2 -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done
