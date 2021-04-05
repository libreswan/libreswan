: ==== cut ====
ipsec auto --status
ipsec stop
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
