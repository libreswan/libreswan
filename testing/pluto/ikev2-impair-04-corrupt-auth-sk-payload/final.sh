: only one SKEYSEED operation
grep 'offloading IKEv2 SKEYSEED' /tmp/pluto.log | wc -l
../../pluto/bin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
