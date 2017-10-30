: ==== cut ====
journalctl /sbin/ocspd --no-pager | tail -n 20
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
