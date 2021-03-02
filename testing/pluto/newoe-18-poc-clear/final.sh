../../pluto/bin/ipsec-look.sh
# should not show any hits
grep -v '^|' /tmp/pluto.log | grep "negotiated connection"
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
