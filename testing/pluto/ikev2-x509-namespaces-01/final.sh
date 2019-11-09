hostname | grep east > /dev/null && ipsec whack --trafficstatus
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
