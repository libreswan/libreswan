ipsec auto --up  westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
../../guestbin/ipsec-look.sh
# wait for rekey event
sleep 5
ipsec whack --rekey-ike --name 1
# rekey of IPsec SA means traffic counters should be 0
ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
../../guestbin/ipsec-look.sh
: done
