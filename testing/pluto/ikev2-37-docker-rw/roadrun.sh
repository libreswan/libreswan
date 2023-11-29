ipsec auto --up road-eastnet-nonat
../../guestbin/ping-once.sh --up -I 192.0.2.219  192.0.2.254
ipsec whack --trafficstatus
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
echo done
