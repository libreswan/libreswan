# one ping to trigger IKE
ping -q -w 1 -n -c 1 -I 192.0.3.254 192.0.2.254
sleep 4
# success
ping -q -w 4 -n -c 4 -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done
