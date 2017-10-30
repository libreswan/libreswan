ipsec whack --trafficstatus
ipsec whack --shuntstatus
ipsec look
ipsec look
grep "message ID:" /tmp/pluto.log
# grep on east
hostname |grep west > /dev/null || grep -A 1 "has not responded in" /tmp/pluto.log
# A tunnel should have established
grep "negotiated connection" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
