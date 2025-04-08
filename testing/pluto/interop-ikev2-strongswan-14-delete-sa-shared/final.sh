if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan status ; fi
ipsec _kernel state
ipsec _kernel policy
