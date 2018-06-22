# Confirm expired IPsec SA will not trigger a liveness probe
grep "liveness: no need to send"  /tmp/pluto.log
: ==== cut ====
# stop pluto so if test case is ran manually and left, no legit liveness probes are done
ipsec stop
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
