if [ -f /var/run/pluto/pluto.pid ]; then ../../guestbin/ipsec-look.sh ; fi
if [ -f /var/run/pluto/pluto.pid ]; then grep -E "Message ID: [0-9] " /tmp/pluto.log  ; fi
if [ -f /var/run/charon.pid -o -f /var/run/strongswan/charon.pid ]; then strongswan status ; fi
