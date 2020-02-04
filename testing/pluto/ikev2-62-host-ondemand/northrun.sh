# one ping to trigger IKE
../../pluto/bin/ping-once.sh --forget -I 192.0.3.254 192.0.2.254
../../pluto/bin/wait-for.sh --match north-east -- ipsec whack --trafficstatus
# success
../../pluto/bin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done
