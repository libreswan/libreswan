crlutil -L -d sql:/etc/ipsec.d | grep mainca
ipsec auto --listall | grep -A10 "List of CRLs" | egrep 'Issuer|Entry|Serial'
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
