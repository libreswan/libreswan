# give east 60s for:
# "west-east-auto" #1: received Delete SA payload: replace IPSEC State #2 in 60 seconds
sleep 45
sleep 30
# no IPsec SA should be up - ISAKMP SA should be gone too
ipsec whack --trafficstatus
ipsec status |grep west-east
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -n "`ls /tmp/core* 2>/dev/null`" ]; then echo CORE FOUND; mv /tmp/core* OUTPUT/; fi
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
