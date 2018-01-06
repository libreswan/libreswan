# There should not be any R_U_THERE packets from either end because we are not idle
grep R_U_THERE /tmp/pluto.log
: ==== cut ====
# stop pluto so if test case is ran manually and left, no legit DPDs are done
ipsec stop
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
