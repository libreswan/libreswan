: ==== cut ====
ipsec auto --status
ipsec stop
: ==== tuc ====
grep "^leak" /tmp/pluto.log
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
