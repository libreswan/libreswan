# TODO  put in a grep line confirming NO PPK usage
ipsec whack --shutdown
grep leak /tmp/pluto.log
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
