# should be empty if east triggered
hostname | grep west > /dev/null || ipsec whack --trafficstatus
grep "message ID:" /tmp/pluto.log
# grep on east
hostname | grep west > /dev/null || grep -A 1 "has not responded in" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
