# road, the client with the single IP, initiates two rekeys; with pfs-info
# these are optimized: no TS payloads are sent, so the new Child SA has to
# inherit the narrowed selectors
ipsec whack --rekey-child --name road-east-x509-ipv4
../../guestbin/wait-for.sh --match '#3: initiator rekeyed Child SA #2' -- cat /tmp/pluto.log
ipsec whack --rekey-child --name road-east-x509-ipv4
../../guestbin/wait-for.sh --match '#4: initiator rekeyed Child SA #3' -- cat /tmp/pluto.log
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
# still the same selectors
ipsec whack --trafficstatus
ipsec _kernel policy | grep -E '^src'
