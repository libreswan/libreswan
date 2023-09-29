HEAD=$(ip xfrm state |grep "enc "|head -1)
TAIL=$(ip xfrm state |grep "enc "|tail -1)
if [ "$HEAD" = "$TAIL" ]; then echo "ERROR: inbound and outbound key are the same!"; fi
if [ -f /var/run/pluto/pluto.pid ]; then ../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan statusall ; fi
