if [ -f /var/run/pluto/pluto.pid ]; then ipsec look ; fi
if [ -f /var/run/charon.pid ]; then strongswan statusall ; fi
: ==== cut ====
if [ -f /var/run/pluto/pluto.pid ]; then ipsec auto --status ; fi
if [ -f /var/run/charon.pid ]; then strongswan statusall ; fi
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* ./; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
