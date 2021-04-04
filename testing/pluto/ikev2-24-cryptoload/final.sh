../../pluto/bin/ipsec-look.sh
ipsec stop
grep -e leak /tmp/pluto.log | grep -v -e '|'
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
