if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan status ; fi
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
