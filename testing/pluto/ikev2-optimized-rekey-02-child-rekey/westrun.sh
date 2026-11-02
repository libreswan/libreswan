ipsec auto --up westnet-eastnet-ikev2
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
# first rekey of the IKE_AUTH Child SA: not optimized, no pfs-info
ipsec whack --rekey-child --name westnet-eastnet-ikev2
../../guestbin/wait-for.sh --match '#3: initiator rekeyed Child SA #2' -- cat /tmp/pluto.log
# second rekey: optimized
ipsec whack --rekey-child --name westnet-eastnet-ikev2
../../guestbin/wait-for.sh --match '#4: initiator rekeyed Child SA #3' -- cat /tmp/pluto.log
../../guestbin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
ipsec whack --trafficstatus
echo done
