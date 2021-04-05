: expect only one SKEYSEED operation
grep 'calculating skeyseed' /tmp/pluto.log | wc -l
../../guestbin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
