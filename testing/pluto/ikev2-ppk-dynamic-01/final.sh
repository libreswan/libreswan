ipsec whack --shutdown
grep -e leak /tmp/pluto.log | grep -v -e '|'
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
