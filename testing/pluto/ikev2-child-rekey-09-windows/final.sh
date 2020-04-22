# only #3 and not #2 in trafficstatus output
ipsec whack --trafficstatus
# output should be empty
grep "Notify Message Type: v2N_TS_UNACCEPTABLE" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
