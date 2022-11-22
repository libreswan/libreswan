if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan statusall ; fi
../../guestbin/kernel-state.sh
../../guestbin/kernel-policy.sh
