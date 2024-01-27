ipsec auto --up eastnet-any
../../guestbin/ping-once.sh --up -I 100.64.13.2 192.0.2.254
ipsec whack --trafficstatus
ipsec whack --rekey-child --name eastnet-any
# not using: ipsec auto --up eastnet-any
../../guestbin/ping-once.sh --up -I 100.64.13.2 192.0.2.254
ipsec whack --trafficstatus
echo done
