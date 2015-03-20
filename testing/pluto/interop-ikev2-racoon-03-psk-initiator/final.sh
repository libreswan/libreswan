: ==== cut ====
if [ -n "`pidof pluto`" ]; then ipsec auto --status; fi
cat /tmp/*.log
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* ./; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
