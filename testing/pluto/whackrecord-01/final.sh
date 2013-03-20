ipsec look
ipsec setup stop
: ==== cut ====
od -x /var/tmp/east.record | sed 3q
sed 1q /var/tmp/east.record
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* ./; fi
if [ -f /sbin/ausearch ]; then ausearch -m avc -ts recent | grep -v 'no matches'; fi
: ==== end ====
