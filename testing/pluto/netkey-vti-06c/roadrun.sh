ipsec auto --up  road-east-vti
# since we have vti-routing=no, no marking, so unencryted pacets are dropped
ping -n -c 4  192.0.2.254
ipsec whack --trafficstatus
ip ro add 192.0.2.0/24 dev vti0
# now packets into vti0 device will get marked, and encrypted and counted
ping -n -c 4 192.0.2.254
ipsec whack --trafficstatus
echo done
