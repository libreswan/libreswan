ipsec _kernel state
ipsec _kernel policy
if [ -f /var/run/pluto/pluto.pid ]; then ipsec whack --trafficstatus ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan status ; fi
sleep 7
