ipsec auto --up road-eastnet-nonat
../../guestbin/ping-once.sh --up -I 192.0.2.219  192.0.2.254
ipsec whack --trafficstatus
ipsec _kernel state
ipsec _kernel policy
echo done
