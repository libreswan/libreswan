ipsec look
ipsec setup stop
: ==== cut ====
od -x /var/tmp/east.record | sed 3q
sed 1q /var/tmp/east.record
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
