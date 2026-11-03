# road was the responder of that optimized rekey
../../guestbin/wait-for.sh --match '#5: responder rekeyed Child SA #4' -- cat /tmp/pluto.log
../../guestbin/ping-once.sh --up -I 192.0.2.100 192.1.2.23
# and still the same selectors
ipsec trafficstatus
ipsec _kernel policy | grep -E '^src'
