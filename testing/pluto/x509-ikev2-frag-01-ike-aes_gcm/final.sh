grep -e 'fragment number:' -e 'total fragments:' /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
