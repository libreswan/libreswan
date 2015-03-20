if [ -f /var/run/pluto/pluto.pid ]; then ipsec auto --down westnet-eastnet-ikev2 ; fi
if [ -f /var/run/charon.pid ]; then sleep 5 ; fi
#
if [ -f /var/run/pluto/pluto.pid ]; then ipsec look ; fi
if [ -f /var/run/pluto/pluto.pid ]; then grep "message ID:" /tmp/pluto.log  ; fi
if [ -f /var/run/charon.pid ]; then strongswan status ; fi
: ==== cut ====
if [ -f /var/run/pluto/pluto.pid ]; then ipsec auto --status ; fi
if [ -f /var/run/charon.pid ]; then strongswan statusall ; fi
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
