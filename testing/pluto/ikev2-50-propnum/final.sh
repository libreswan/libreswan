: dump all emitted and parsed proposals onto the console
: weird pattern deals with optional length field
grep -B 1 -e '|    last proposal: ' -A 3 -e '|    prop #: ' /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
