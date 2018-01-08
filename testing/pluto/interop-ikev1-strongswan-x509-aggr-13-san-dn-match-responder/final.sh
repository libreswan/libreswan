# confirm the right ID types were sent/received
grep "ID type" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
ipsec stop
strongswan stop
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
