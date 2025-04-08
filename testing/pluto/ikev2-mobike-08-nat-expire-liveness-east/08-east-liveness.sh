ipsec _kernel state
cat /proc/net/xfrm_stat
# the ping stops liveness; this is a debug message!
../../guestbin/wait-for.sh --match 'recent IPsec traffic' -- cat /tmp/pluto.log | sed -e 's/ [^ ]* seconds/ NNN seconds/g'
# but no further pings let liveness continue
../../guestbin/wait-for-pluto.sh --match '10 second timeout exceeded'
