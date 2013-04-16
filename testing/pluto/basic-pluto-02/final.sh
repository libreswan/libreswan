ipsec look
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /tmp/core ]; then echo CORE FOUND; mv /tmp/core ./; fi
if [ -f /sbin/ausearch ]; then ausearch -m avc -ts recent ; fi
: ==== end ====
