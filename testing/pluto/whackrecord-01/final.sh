ipsec setup stop
ls /var/tmp/east.record
: ==== cut ====
od -x /var/tmp/east.record | sed 3q | strings
sed 1q /var/tmp/east.record | strings
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
