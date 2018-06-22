grep -i "certificate revoked" /tmp/pluto.log
grep ERROR /tmp/pluto.log
: ==== cut ====
journalctl /sbin/ocspd --no-pager | tail -n 20 | grep ocspd
ipsec auto --status
: ==== tuc ====
