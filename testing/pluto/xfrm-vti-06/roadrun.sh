../../guestbin/ip.sh address add 192.0.3.254/24 dev eth0
ipsec auto --up road-east-vti
# since we have vti-routing=no, no marking, so unencrypted packets are dropped
../../guestbin/ping-once.sh --down -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
ip ro add 192.0.2.254/32 dev vti0
# now packets into vti0 device will get marked, and encrypted and counted
../../guestbin/ping-once.sh --up -I 192.0.3.254 192.0.2.254
ipsec whack --trafficstatus
echo done
