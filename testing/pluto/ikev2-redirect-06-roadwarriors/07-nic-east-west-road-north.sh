ipsec whack --trafficstatus
: ==== cut ====
ipsec auto --status
../../pluto/bin/ipsec-look.sh
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
