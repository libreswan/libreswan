ipsec look
ipsec whack --trafficstatus 
# A tunnel should have established
grep "negotiated connection" /tmp/pluto.log
# you should see both RSA and NULL
grep IKEv2_AUTH_ OUTPUT/*pluto.log 
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
