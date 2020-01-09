ipsec status | grep eastnet
# should show no hits
grep INVALID_IKE_SPI /tmp/pluto.log
grep MSG_TRUNC /tmp/pluto.log
grep "cannot route" /tmp/pluto.log
: ==== cut ====
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
