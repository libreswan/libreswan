# only #2 and not #3
ipsec trafficstatus
# should find a match on both east and road
grep "Notify Message Type: v2N_TS_UNACCEPTABLE" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
