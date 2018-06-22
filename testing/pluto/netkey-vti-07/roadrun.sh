ip addr add 192.0.3.254/24 dev eth0
ipsec auto --up  road-east-vti
# since we have vti-routing=no, no marking, so unencrypted packets are dropped
ping -n -c 4 -I 192.0.3.254 192.1.2.23
ipsec whack --trafficstatus
ip ro add 192.1.2.23/32 dev vti0
# now packets into vti0 device will get marked, and encrypted and counted
ping -n -c 4 -I 192.0.3.254 192.1.2.23
ipsec whack --trafficstatus
echo done
