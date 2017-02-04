# A tunnel should have established with non-zero byte counters
ipsec whack --trafficstatus 
# you should see both RSA and NULL
grep IKEv2_AUTH_ /tmp/pluto.log 
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
