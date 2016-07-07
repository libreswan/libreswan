# east should have brought down but NOT re-established the tunnel
ipsec whack --trafficstatus
# can be seen on east logs
hostname | grep west > /dev/null || grep "IKEv2 liveness action:" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
