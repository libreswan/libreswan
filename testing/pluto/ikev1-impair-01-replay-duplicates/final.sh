../../pluto/bin/ipsec-look.sh
sed -n -e '/IMPAIR: start duplicate packet/,/IMPAIR: stop duplicate packet/ { /^[^|]/ p }' /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
