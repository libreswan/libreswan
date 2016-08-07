# should be empty if east triggered
hostname | grep west > /dev/null || ipsec whack --trafficstatus
grep "message ID:" /tmp/pluto.log
# grep on east 
hostname | grep west > /dev/null || grep -A 1 "liveness_check - peer has not responded in" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
