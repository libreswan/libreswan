: ==== cut ====
ipsec auto --status
: ==== tuc ====
grep 'Result using RFC 3947' /tmp/pluto.log
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
