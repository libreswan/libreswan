ipsec auto --up rw-lte
ping -n -q -c 2 -I 100.64.0.1 192.0.2.254
ipsec whack --trafficstatus
ipsec auto --up rw-wifi
# both should remain up and working - aka wifi-assist
ping -n -q -c 2 -I 100.64.0.2 192.0.2.254
ping -n -q -c 2 -I 100.64.0.1 192.0.2.254
ipsec whack --trafficstatus
echo done
