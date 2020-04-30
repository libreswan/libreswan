# IKE #1 CHILD #2
ipsec auto --up west
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# why?
sleep 13
# IKE #3 CHILD #2
ipsec whack --rekey-ike --name west
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
ipsec status |grep STATE_
# why?
sleep 21
# IKE #4 CHILD #2
ipsec whack --rekey-ike --name west
../../pluto/bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec status |grep STATE_
