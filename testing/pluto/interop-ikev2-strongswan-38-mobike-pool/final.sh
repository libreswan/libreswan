if [ -f /var/run/pluto/pluto.pid ]; then ../../guestbin/ipsec-look.sh ; fi
if [ -f /var/run/pluto/pluto.pid ]; then ipsec whack --trafficstatus ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan status ; fi
