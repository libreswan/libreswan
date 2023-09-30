ip xfrm policy
ip xfrm state
if [ -f /var/run/pluto/pluto.pid ]; then ../../guestbin/ipsec-kernel-state.sh ; ../../guestbin/ipsec-kernel-policy.sh ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan statusall ; fi
