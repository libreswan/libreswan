: expect only one SKEYSEED operation
grep 'calculating skeyseed' /tmp/pluto.log | wc -l
../../pluto/bin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
