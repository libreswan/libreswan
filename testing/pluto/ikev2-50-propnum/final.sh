: dump all emitted and parsed proposals onto the console
: weird pattern deals with optional length field
grep -B 1 -e '|    last proposal: ' -A 3 -e '|    prop #: ' /tmp/pluto.log
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
