if [ -f /var/run/pluto/pluto.pid ]; then ipsec status | grep westnet-eastnet-ikev2 ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan status ; fi
