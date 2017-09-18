ping -c 10000 -I  192.0.3.254  192.0.2.254 2>&1 >/dev/null &
ping -c 10000 -I  192.0.3.254  192.0.2.251 2>&1 >/dev/null &
ping -c 10000 -I  192.0.3.254  192.0.22.254 2>&1 >/dev/null &
ping -c 10000 -I  192.0.3.254  192.0.22.251 2>&1 >/dev/null &
ipsec auto --start north-eastnets
ipsec auto --status | grep north-eastnets
ping -n -c 2 -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done
