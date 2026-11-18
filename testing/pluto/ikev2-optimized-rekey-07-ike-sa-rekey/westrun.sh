ipsec up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# rekey the IKE SA: optimized
ipsec whack --rekey-ike --name westnet-eastnet-ikev2
../../guestbin/wait-for.sh --match '#3: initiator rekeyed IKE SA #1' -- cat /tmp/pluto.log
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# and again
ipsec whack --rekey-ike --name westnet-eastnet-ikev2
../../guestbin/wait-for.sh --match '#4: initiator rekeyed IKE SA #3' -- cat /tmp/pluto.log
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec showstates
ipsec trafficstatus
echo done
