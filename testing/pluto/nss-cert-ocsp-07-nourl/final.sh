# on east, revocation should show up
grep "certificate revoked" /tmp/pluto.log
: ==== cut ====
journalctl /sbin/ocspd --no-pager | tail -n 20
# tunnel should not show up
ipsec status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
