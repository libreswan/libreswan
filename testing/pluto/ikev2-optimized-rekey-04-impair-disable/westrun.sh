ipsec up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# with pfs-info the first rekey would be optimized; disable that so
# the traditional rekey, with SA and TS, is used
ipsec whack --impair disable_optimized_rekey
ipsec whack --rekey-child --name westnet-eastnet-ikev2
../../guestbin/wait-for.sh --match '#3: initiator rekeyed Child SA #2' -- cat /tmp/pluto.log
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec trafficstatus
echo done
