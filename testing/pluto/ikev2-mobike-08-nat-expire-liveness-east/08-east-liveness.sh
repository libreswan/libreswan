../../guestbin/ipsec-kernel-state.sh
cat /proc/net/xfrm_stat
# the ping stops liveness
../../guestbin/wait-for-pluto.sh --match 'recent IPsec traffic' | sed -e 's/ [^ ]* seconds/ NNN seconds/g'
# but no further pings let liveness continue
../../guestbin/wait-for-pluto.sh --match '10 second timeout exceeded'
