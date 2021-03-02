ipsec auto --up west-east-ikev2
ping -n -c 4 192.1.2.23
ipsec whack --trafficstatus
echo done
