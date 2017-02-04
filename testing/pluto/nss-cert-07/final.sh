certutil -L -d sql:/etc/ipsec.d
certutil -L -d sql:/etc/ipsec.d
# catch any cert chain specific leaks
ipsec whack --shutdown
grep leak /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
