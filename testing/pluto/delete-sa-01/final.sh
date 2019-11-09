../../pluto/bin/ipsec-look.sh
# up to 3.26 we printed a bogus message, this is checking that no longer happens
grep "received and ignored empty informational" /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
