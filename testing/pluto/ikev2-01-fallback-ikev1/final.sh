../../pluto/bin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
ipsec stop
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
