ipsec look
: ==== cut ====
ipsec auto --status
: ==== tuc ====
grep 'Result using RFC 3947' /tmp/pluto.log
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* ./; fi
if [ -f /sbin/ausearch ]; then ausearch -m avc -ts recent | grep -v 'no matches'; fi
: ==== end ====
