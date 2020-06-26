ipsec look
grep '^connection from' /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
ipsec stop
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
