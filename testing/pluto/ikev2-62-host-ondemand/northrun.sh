# one ping to trigger IKE
../../pluto/bin/one-ping.sh -I 192.0.3.254 192.0.2.254
../../pluto/bin/wait-for-whack-trafficstatus.sh north-east
# success
ping -q -w 4 -n -c 4 -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done
