ipsec look
grep -A 1 KEY_LENGTH /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
ipsec whack --shutdown
: ==== cut ====
ipsec look
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* ./; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
