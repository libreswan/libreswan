../../pluto/bin/ipsec-look.sh
sed -n -e '/IMPAIR: start processing replay forward/,/IMPAIR: stop processing replay forward/ { /^[^|]/ p }' /tmp/pluto.log | grep -v 'message arrived'
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
