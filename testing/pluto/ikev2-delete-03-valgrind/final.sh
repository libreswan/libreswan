ipsec look
ipsec auto --status
if [ -f  /var/run/pluto/pluto.pid ]; then kill `cat /var/run/pluto/pluto.pid` ; fi
sleep 2
ps -ax | grep pluto
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
