ipsec look
ipsec setup stop
: ==== cut ====
od -x /var/tmp/east.record | sed 3q
sed 1q /var/tmp/east.record
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
