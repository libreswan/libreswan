# confirm PPK was used
grep "PPK AUTH calculated" /tmp/pluto.log
ipsec whack --shutdown
grep leak /tmp/pluto.log
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
