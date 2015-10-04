ipsec look
if [ -f /etc/pam.d/pluto.stock ]; then mv /etc/pam.d/pluto.stock /etc/pam.d/pluto ; fi
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
