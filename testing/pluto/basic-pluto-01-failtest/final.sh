../../pluto/bin/ipsec-look.sh
# normally xfrmcheck should never fail, but this tests the test :)
../bin/xfrmcheck.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
