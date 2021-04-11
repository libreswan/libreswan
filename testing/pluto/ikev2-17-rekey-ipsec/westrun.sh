ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
# wait for rekey event
sleep 20
sleep 20
sleep 20
sleep 20
# rekey of IPsec SA means traffic counters should be 0
ipsec whack --trafficstatus
echo done
