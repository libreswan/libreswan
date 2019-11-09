../../pluto/bin/ipsec-look.sh
grep "minor version" /tmp/pluto.log >/dev/null && echo payload found
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
