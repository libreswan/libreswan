ipsec auto --up westnet-eastnet-ikev2a
ping -n -q -w 4 -c 4 -I 192.0.1.254 192.0.2.254
ipsec auto --up westnet-eastnet-ikev2b
ping -n -q -w 4 -c 4 -I 192.0.100.254 192.0.200.254
ipsec auto --up westnet-eastnet-ikev2c
ping -n -q -w 4 -c 4 -I 192.0.101.254 192.0.201.254
ipsec whack --trafficstatus
ipsec status |grep STATE_
echo "sleep 23"
sleep 23
ping -n -q -w 4 -c 4 -I 192.0.1.254 192.0.2.254
ping -n -q -w 4 -c 4 -I 192.0.100.254 192.0.200.254
ping -n -q -w 4 -c 4 -I 192.0.101.254 192.0.201.254
ipsec whack --trafficstatus
ipsec status |grep STATE_
echo "sleep 25"
sleep 25
ping -n -q -w 4 -c 4 -I 192.0.1.254 192.0.2.254
ping -n -q -w 4 -c 4 -I 192.0.100.254 192.0.200.254
ping -n -q -w 4 -c 4 -I 192.0.101.254 192.0.201.254
echo done
