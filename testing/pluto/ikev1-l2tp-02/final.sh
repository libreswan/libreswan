../../pluto/bin/ipsec-look.sh
: ==== cut ====
ipsec auto --status
cat /tmp/xl2tpd.log
: ==== tuc ====
grep 'Result using RFC 3947' /tmp/pluto.log
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
