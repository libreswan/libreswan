# only expected to show failure on west
grep "ERROR" /tmp/pluto.log

: ==== cut ====
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
