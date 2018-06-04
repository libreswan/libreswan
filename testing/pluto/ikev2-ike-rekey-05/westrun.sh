ipsec auto --up westnet-eastnet-a
ping -w 4 -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec auto --up westnet-eastnet-b
ping -w 4 -n -c 4 -I 192.0.100.254 192.0.200.254
ipsec auto --up westnet-eastnet-c
ping -w 4 -n -c 4 -I 192.0.101.254 192.0.201.254
ipsec whack --trafficstatus
ipsec status |grep STATE_
echo sleep 3m
sleep 60
sleep 60
sleep 60
ipsec whack --trafficstatus
ipsec status |grep STATE_
sleep 60
ipsec whack --trafficstatus
ipsec status |grep STATE_
sleep 60
sleep 60
sleep 60
sleep 60
sleep 60
echo done
