# east, the server with the pool, initiates the optimized rekey of the
# Child SA that road rekeyed
ipsec whack --rekey-child --name '"rw-east-pool-x509-ipv4"[1]'
../../guestbin/wait-for.sh --match '#5: initiator rekeyed Child SA #4' -- cat /tmp/pluto.log
ipsec whack --trafficstatus
ipsec _kernel policy | grep -E '^src'
