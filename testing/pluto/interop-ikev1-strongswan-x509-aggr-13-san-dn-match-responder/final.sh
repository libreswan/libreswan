# confirm the right ID types were sent/received
grep "ID type" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
ipsec stop
strongswan stop
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
