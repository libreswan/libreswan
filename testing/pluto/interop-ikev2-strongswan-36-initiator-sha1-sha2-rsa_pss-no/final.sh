if [ -f /var/run/pluto/pluto.pid ]; then ../../guestbin/ipsec-kernel-state.sh\n../../guestbin/ipsec-kernel-policy.sh ; fi
# expect state #2, state #1 responded with INVALID_KE
if [ -f /var/run/pluto/pluto.pid ]; then grep " authenticated peer " /tmp/pluto.log ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan status ; fi
