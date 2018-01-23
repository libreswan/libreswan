ipsec whack --shutdown
grep leak /tmp/pluto.log
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
