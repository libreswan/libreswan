../../pluto/bin/ipsec-look.sh
ipsec whack --trafficstatus
grep "MOBIKE " /tmp/pluto.log
sleep 7
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
