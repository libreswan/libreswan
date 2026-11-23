ipsec up transport-optimized-rekey
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
# with pfs-info the first rekey is optimized; neither end sends
# USE_TRANSPORT_MODE but the mode is inherited
ipsec whack --rekey-child --name transport-optimized-rekey
../../guestbin/wait-for.sh --match '#3: initiator rekeyed Child SA #2' -- cat /tmp/pluto.log
ipsec whack --rekey-child --name transport-optimized-rekey
../../guestbin/wait-for.sh --match '#4: initiator rekeyed Child SA #3' -- cat /tmp/pluto.log
# confirm transport mode is still used after the rekeys
ipsec _kernel state | grep mode
../../guestbin/ping-once.sh --up -I 192.1.2.45 192.1.2.23
ipsec trafficstatus
echo done
