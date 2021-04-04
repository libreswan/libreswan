# confirm the right ID types were sent/received
grep "ID type" /tmp/pluto.log | sort | uniq
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
