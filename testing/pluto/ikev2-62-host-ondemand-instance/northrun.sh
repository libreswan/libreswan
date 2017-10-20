# ipsec auto --add north-east
ping -q -w 4 -n -c 4 -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done
