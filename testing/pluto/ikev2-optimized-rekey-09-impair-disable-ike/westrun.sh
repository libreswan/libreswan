ipsec up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# with the optimized rekey impaired both rekeys have to be regular
ipsec whack --impair disable_optimized_rekey
ipsec whack --rekey-child --name westnet-eastnet-ikev2
ipsec whack --rekey-ike --name westnet-eastnet-ikev2
# without the impairment both rekeys are optimized
ipsec whack --no-impair disable_optimized_rekey
ipsec whack --rekey-child --name westnet-eastnet-ikev2
ipsec whack --rekey-ike --name westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec showstates
ipsec trafficstatus
echo done
