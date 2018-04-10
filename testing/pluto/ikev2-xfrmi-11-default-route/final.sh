: ==== cut ====
ipsec whack --trafficstatus
../../pluto/bin/ipsec-look.sh
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
