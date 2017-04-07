# should not match anything
grep "already in use" /tmp/pluto.log
# should only show 1 connection
ipsec whack --trafficstatus
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
