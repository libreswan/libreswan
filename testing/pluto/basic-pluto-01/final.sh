ipsec look
: ==== cut ====
ipsec auto --status
: ==== tuc ====
ipsec whack --shutdown
ipsec look
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* ./; fi
if [ -f /sbin/ausearch ]; then ausearch -m avc -ts recent ; fi
: ==== end ====
