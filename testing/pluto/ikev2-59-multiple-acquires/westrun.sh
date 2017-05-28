ping -c 10000 -I  192.0.1.254  192.0.2.254 2>&1 >/dev/null &
ping -c 10000 -I  192.0.1.254  192.0.2.254 2>&1 >/dev/null &
ping -c 10000 -I  192.0.1.254  192.0.2.254 2>&1 >/dev/null &
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --up  westnet-eastnet-ikev2
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
