ipsec look
grep '^connection from' /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
ipsec stop
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
