: ==== cut ====
ipsec auto --status
: ==== tuc ====
ipsec stop
egrep -i "IKE|ipsec-" /var/log/audit/audit.log
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
